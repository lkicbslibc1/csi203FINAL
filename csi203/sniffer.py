import socketio
import threading
import time
from scapy.all import *
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, conf, load_layer

# โหลด TLS Layer ให้ Scapy รู้จัก
load_layer("tls")

try:
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import (
        TLSClientHello, TLSServerHello, TLSCertificate,
        TLS13ClientHello, TLS13ServerHello, TLS13Certificate
    )
    from scapy.layers.tls.extensions import TLS_Ext_SupportedVersion_SH
    from scapy.layers.tls.cert import Cert
    from scapy.layers.x509 import X509_Cert
    TLS_AVAILABLE = True
    print("✅ Scapy TLS layers loaded successfully")
except ImportError as e:
    print(f"⚠️ TLS layers not fully available: {e}")
    TLS_AVAILABLE = False

# =============================================
# บังคับผูก (bind) port 443 กับ TLS layer
# ถ้าไม่ทำ Scapy จะไม่ dissect TLS ให้อัตโนมัติ
# =============================================
try:
    from scapy.layers.tls.record import TLS
    bind_layers(TCP, TLS, sport=443)
    bind_layers(TCP, TLS, dport=443)
    print("✅ Bound TCP:443 -> TLS layer")
except Exception as e:
    print(f"⚠️ Could not bind TLS layer: {e}")

# --- ตั้งค่าการเชื่อมต่อ ---
sio = socketio.Client()
sniff_thread = None
stop_event = threading.Event()
total_bytes = 0
stats_thread_started = False


def get_available_ifaces():
    iface_list = []
    for iface in conf.ifaces.values():
        iface_list.append({"name": iface.name, "description": iface.description})
    return iface_list


# =============================================
# ฟังก์ชันหลัก: ดึง TLS Version จริงๆ
# - TLS 1.2: record layer = 0x0303, ไม่มี supported_versions ext
# - TLS 1.3: record layer = 0x0303 เหมือนกันแต่มี supported_versions ext ที่บอก 0x0304
# =============================================
TLS_VERSION_MAP = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

RECORD_TYPE_MAP = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
}


def get_tls_version_from_raw(payload):
    """อ่าน TLS version จาก raw bytes ของ Record Layer"""
    if len(payload) >= 3 and payload[0] in [0x14, 0x15, 0x16, 0x17]:
        major = payload[1]
        minor = payload[2]
        version_num = (major << 8) | minor
        record_type = RECORD_TYPE_MAP.get(payload[0], "Unknown")
        version_str = TLS_VERSION_MAP.get(version_num, f"Unknown (0x{version_num:04x})")
        return version_str, record_type
    return "N/A", "N/A"


def get_true_tls_version(packet, raw_version):
    """
    ระบุ TLS version ที่แท้จริง:
    - TLS13ServerHello -> TLS 1.3 แน่นอน
    - TLSServerHello + TLS_Ext_SupportedVersion_SH -> TLS 1.3
    - TLSServerHello ธรรมดา -> ดูจาก version field
    - fallback ไป raw_version
    """
    try:
        # Scapy 2.7 แยก TLS 1.3 ServerHello เป็น class ต่างหาก
        if packet.haslayer(TLS13ServerHello):
            return "TLS 1.3"
        
        if packet.haslayer(TLSServerHello):
            sh = packet.getlayer(TLSServerHello)
            
            # เช็ค supported_versions extension (ใช้ class ตรงจาก Scapy 2.7)
            if packet.haslayer(TLS_Ext_SupportedVersion_SH):
                sv = packet.getlayer(TLS_Ext_SupportedVersion_SH)
                v = getattr(sv, 'version', None)
                if v is not None and isinstance(v, int):
                    return TLS_VERSION_MAP.get(v, f"TLS (0x{v:04x})")
            
            # fallback: ลองหาใน ext list
            if hasattr(sh, 'ext') and sh.ext:
                for ext in sh.ext:
                    if isinstance(ext, TLS_Ext_SupportedVersion_SH):
                        v = getattr(ext, 'version', None)
                        if v is not None and isinstance(v, int):
                            return TLS_VERSION_MAP.get(v, f"TLS (0x{v:04x})")
            
            # ถ้าไม่มี extension -> ใช้ version field ตรงๆ (TLS 1.2 หรือต่ำกว่า)
            if hasattr(sh, 'version'):
                v = sh.version
                if isinstance(v, int):
                    return TLS_VERSION_MAP.get(v, f"TLS (0x{v:04x})")
                    
    except Exception as e:
        print(f"  [debug] get_true_tls_version error: {e}")
    
    return raw_version


def extract_cipher(packet):
    """ดึง Cipher Suite จาก ServerHello"""
    try:
        if packet.haslayer(TLSServerHello):
            sh = packet.getlayer(TLSServerHello)
            # ใช้ sprintf เพื่อแปลง cipher_suite number เป็นชื่อ
            cs = sh.sprintf("%cipher_suite%")
            if cs and cs != "None":
                return cs
            # fallback: ลองอ่าน field ตรงๆ
            if hasattr(sh, 'cipher_suite'):
                return f"0x{sh.cipher_suite:04X}"
        
        if packet.haslayer(TLSClientHello):
            ch = packet.getlayer(TLSClientHello)
            suites = getattr(ch, 'ciphers', [])
            if suites:
                count = len(suites) if hasattr(suites, '__len__') else 0
                return f"ClientHello ({count} suites proposed)"
    except Exception as e:
        print(f"  [debug] extract_cipher error: {e}")
    return "N/A"


def extract_certificate_info(packet):
    """
    ดึงข้อมูล Certificate:
    - Issuer (ผู้ออก cert)
    - Subject (เจ้าของ cert)
    - Not Before / Not After (วันหมดอายุ)
    - SAN (Subject Alternative Name)
    """
    cert_details = {}
    try:
        # รองรับทั้ง TLS 1.2 (TLSCertificate) และ TLS 1.3 (TLS13Certificate)
        cert_layer = None
        if packet.haslayer(TLSCertificate):
            cert_layer = packet.getlayer(TLSCertificate)
        elif packet.haslayer(TLS13Certificate):
            cert_layer = packet.getlayer(TLS13Certificate)
        
        if cert_layer is None:
            return None
        
        # Scapy เก็บ cert ไว้ใน certs field เป็น list ของ certificate
        certs_data = getattr(cert_layer, 'certs', [])
        if not certs_data:
            # บางเวอร์ชันของ Scapy ใช้ชื่อ field อื่น
            certs_data = getattr(cert_layer, 'certslist', [])
        
        if certs_data:
            for cert_entry in certs_data:
                # แต่ละ entry อาจเป็น ASN1_CERT structure หรือ X509_Cert
                cert_obj = None
                
                if hasattr(cert_entry, 'cert'):
                    cert_obj = cert_entry.cert
                elif hasattr(cert_entry, 'data'):
                    cert_obj = cert_entry.data
                else:
                    cert_obj = cert_entry
                    
                # ลอง parse ด้วย Scapy classes
                if cert_obj:
                    try:
                        # ถ้าเป็น X509_Cert (Scapy 2.7 ใช้ class นี้)
                        if isinstance(cert_obj, X509_Cert):
                            tbs = cert_obj.tbsCertificate
                            if hasattr(tbs, 'subject'):
                                cert_details['subject'] = tbs.subject.human_readable() if hasattr(tbs.subject, 'human_readable') else str(tbs.subject)
                            if hasattr(tbs, 'issuer'):
                                cert_details['issuer'] = tbs.issuer.human_readable() if hasattr(tbs.issuer, 'human_readable') else str(tbs.issuer)
                            if hasattr(tbs, 'validity'):
                                val = tbs.validity
                                if hasattr(val, 'not_before'):
                                    cert_details['not_before'] = str(val.not_before.val) if hasattr(val.not_before, 'val') else str(val.not_before)
                                elif hasattr(val, 'notBefore'):
                                    cert_details['not_before'] = str(val.notBefore.val) if hasattr(val.notBefore, 'val') else str(val.notBefore)
                                if hasattr(val, 'not_after'):
                                    cert_details['not_after'] = str(val.not_after.val) if hasattr(val.not_after, 'val') else str(val.not_after)
                                elif hasattr(val, 'notAfter'):
                                    cert_details['not_after'] = str(val.notAfter.val) if hasattr(val.notAfter, 'val') else str(val.notAfter)
                            # ดึง SAN จาก extensions
                            if hasattr(tbs, 'extensions'):
                                for ext_seq in tbs.extensions:
                                    if hasattr(ext_seq, 'extnID') and '2.5.29.17' in str(ext_seq.extnID):
                                        cert_details['san'] = str(ext_seq.extnValue)
                        elif isinstance(cert_obj, Cert):
                            c = cert_obj
                            if hasattr(c, 'subject'): cert_details['subject'] = str(c.subject)
                            if hasattr(c, 'issuer'): cert_details['issuer'] = str(c.issuer)
                            if hasattr(c, 'notBefore'): cert_details['not_before'] = str(c.notBefore)
                            if hasattr(c, 'notAfter'): cert_details['not_after'] = str(c.notAfter)
                            if hasattr(c, 'subjectAltName'): cert_details['san'] = str(c.subjectAltName)
                        elif isinstance(cert_obj, bytes):
                            # ให้ cryptography library จัดการ (fallback ด้านล่าง)
                            pass
                        
                        # เจอ cert ใบแรก (leaf) ก็พอ
                        if cert_details:
                            break
                    except Exception as e:
                        print(f"  [debug] cert parse inner: {e}")
                        continue
        
        # ถ้าดึงจาก object ไม่ได้ ลองใช้ x509 library (fallback)
        if not cert_details:
            try:
                from cryptography import x509
                from cryptography.x509.oid import NameOID, ExtensionOID
                
                raw_certs = getattr(cert_layer, 'certs', getattr(cert_layer, 'certslist', []))
                for cert_entry in raw_certs:
                    cert_bytes = None
                    if hasattr(cert_entry, 'cert') and isinstance(cert_entry.cert, bytes):
                        cert_bytes = cert_entry.cert
                    elif hasattr(cert_entry, 'data') and isinstance(cert_entry.data, bytes):
                        cert_bytes = cert_entry.data
                    elif isinstance(cert_entry, bytes):
                        cert_bytes = cert_entry
                    
                    if cert_bytes:
                        cert_x509 = x509.load_der_x509_certificate(cert_bytes)
                        cert_details['subject'] = cert_x509.subject.rfc4514_string()
                        cert_details['issuer'] = cert_x509.issuer.rfc4514_string()
                        cert_details['not_before'] = str(cert_x509.not_valid_before_utc)
                        cert_details['not_after'] = str(cert_x509.not_valid_after_utc)
                        
                        try:
                            san_ext = cert_x509.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                            san_names = san_ext.value.get_values_for_type(x509.DNSName)
                            cert_details['san'] = ", ".join(san_names)
                        except x509.ExtensionNotFound:
                            pass
                        break
            except ImportError:
                pass
            except Exception as e:
                print(f"  [debug] x509 fallback: {e}")
                
    except Exception as e:
        print(f"  [debug] extract_certificate_info: {e}")
    
    return cert_details if cert_details else None


def get_handshake_type(packet):
    """ระบุประเภทของ TLS Handshake message"""
    types = []
    try:
        if packet.haslayer(TLSClientHello) or packet.haslayer(TLS13ClientHello):
            types.append("ClientHello")
        if packet.haslayer(TLSServerHello) or packet.haslayer(TLS13ServerHello):
            types.append("ServerHello")
        if packet.haslayer(TLSCertificate) or packet.haslayer(TLS13Certificate):
            types.append("Certificate")
    except Exception:
        pass
    return types


# --- Thread สำหรับส่งความเร็วเน็ต ---
def emit_network_stats():
    global total_bytes
    while not stop_event.is_set():
        if sio.connected:
            sio.emit('network_stats', {'bytes': total_bytes})
        total_bytes = 0
        time.sleep(1)


def analyze_packet(packet):
    global total_bytes

    try:
        if not packet.haslayer(IP):
            return
            
        ip_layer = packet.getlayer(IP)
        pkt_size = len(packet)
        total_bytes += pkt_size

        proto = "OTHER"
        port = "-"
        cipher = "N/A"
        cert_info = "N/A"
        cert_details = None
        tls_ver = "N/A"
        payload_preview = "N/A"
        handshake_type = ""
        record_type = "N/A"

        if packet.haslayer(TCP):
            proto = "TCP"
            port = packet[TCP].dport
            sport = packet[TCP].sport
            if sport == 3000 or port == 3000:
                return
            elif sport == 3306 or port == 3306:
                return

            elif port == 80 or sport == 80:
                proto = "HTTP"
            elif port == 443 or sport == 443:
                # ดึง raw bytes ของ TCP payload
                # เนื่องจาก bind_layers(TCP, TLS) ทำให้ Scapy แปลง Raw → TLS layer
                # ดังนั้น Raw layer อาจหายไป → ต้องใช้ bytes(packet[TCP].payload) แทน
                tcp_payload = bytes(packet[TCP].payload)
                
                if len(tcp_payload) >= 3:
                    tls_ver, record_type = get_tls_version_from_raw(tcp_payload)
                
                # Step 2: ถ้า Scapy dissect เป็น TLS layer ได้ (เพราะเรา bind ไว้แล้ว)
                if packet.haslayer(TLS):
                    tls_layer = packet.getlayer(TLS)
                    
                    # ★ อ่าน version จาก TLS record layer ถ้ายังไม่ได้จาก raw
                    if tls_ver == "N/A" and hasattr(tls_layer, 'version'):
                        v = tls_layer.version
                        if isinstance(v, int) and v > 0:
                            tls_ver = TLS_VERSION_MAP.get(v, f"TLS (0x{v:04x})")
                    
                    # ★ ระบุ content type จาก TLS layer
                    if record_type == "N/A" and hasattr(tls_layer, 'type'):
                        record_type = RECORD_TYPE_MAP.get(tls_layer.type, "Unknown")
                    
                    # ดึงประเภท Handshake
                    hs_types = get_handshake_type(packet)
                    
                    if hs_types:
                        handshake_type = " + ".join(hs_types)
                        proto = f"HTTPS (Handshake: {handshake_type}) 🟢"
                        print(f"🔍 TLS Handshake: {handshake_type} | {ip_layer.src} -> {ip_layer.dst}")
                        
                        # ดึง Cipher จาก ServerHello
                        cipher = extract_cipher(packet)
                        
                        # ดึง TLS Version จริง (แยก 1.2 vs 1.3)
                        tls_ver = get_true_tls_version(packet, tls_ver)
                        
                        # ดึง Certificate Details
                        cert_details = extract_certificate_info(packet)
                        if cert_details:
                            cert_info = f"✅ Subject: {cert_details.get('subject', '?')}"
                            print(f"  📜 Certificate: {cert_details}")
                        elif "Certificate" in hs_types:
                            cert_info = "🔄 Certificate (parsing...)"
                            
                        if cipher != "N/A":
                            print(f"  🔐 Cipher: {cipher}")
                        if tls_ver != "N/A":
                            print(f"  📌 TLS Version: {tls_ver}")
                    else:
                        # TLS layer แต่ไม่ใช่ handshake -> เป็น encrypted data
                        if record_type == "ApplicationData":
                            proto = "HTTPS (Data) 🔒"
                        elif record_type == "ChangeCipherSpec":
                            proto = "HTTPS (ChangeCipherSpec) 🔄"
                        elif record_type == "Alert":
                            proto = "HTTPS (Alert) ⚠️"
                        else:
                            proto = "HTTPS (Data) 🔒"
                    
                elif len(tcp_payload) > 0:
                    # Scapy ไม่ dissect เป็น TLS ได้ -> ลองบังคับ parse จาก raw
                    if tcp_payload[0] == 0x16:
                        # Content type 0x16 = Handshake
                        proto = "HTTPS (Handshake) 🟢"
                        print(f"🔍 Raw Handshake detected | {ip_layer.src}:{sport} -> {ip_layer.dst}:{port}")
                        
                        try:
                            forced_tls = TLS(tcp_payload)
                            hs_types = get_handshake_type(forced_tls)
                            if hs_types:
                                handshake_type = " + ".join(hs_types)
                                proto = f"HTTPS (Handshake: {handshake_type}) 🟢"
                            
                            cipher = extract_cipher(forced_tls)
                            tls_ver = get_true_tls_version(forced_tls, tls_ver)
                            cert_details = extract_certificate_info(forced_tls)
                            if cert_details:
                                cert_info = f"✅ Subject: {cert_details.get('subject', '?')}"
                        except Exception as e:
                            print(f"  [debug] forced TLS parse failed: {e}")
                    
                    elif tcp_payload[0] == 0x17:
                        proto = "HTTPS (Data) 🔒"
                    elif tcp_payload[0] == 0x14:
                        proto = "HTTPS (ChangeCipherSpec) 🔄"
                    elif tcp_payload[0] == 0x15:
                        proto = "HTTPS (Alert) ⚠️"
                    else:
                        proto = "HTTPS (ACK)"
                else:
                    proto = "HTTPS (ACK)"

        elif packet.haslayer(UDP):
            proto = "UDP"
            port = packet[UDP].dport
            if port == 53 or packet[UDP].sport == 53:
                proto = "DNS"
            elif port == 443 or packet[UDP].sport == 443:
                proto = "QUIC (HTTP/3)"

        # Payload preview
        if packet.haslayer(Raw):
            payload_preview = packet[Raw].load.hex()[:100] + "..."

        pkt_data = {
            "protocol": proto,
            "src": ip_layer.src,
            "dst": ip_layer.dst,
            "port": port,
            "size": pkt_size,
            "encryption": "Encrypted" if ("HTTPS" in proto or "QUIC" in proto) else "Plaintext",
            "cipher": cipher,
            "cert": cert_info,
            "tls_version": tls_ver,
            "handshake_type": handshake_type,
            "payload": payload_preview,
        }
        
        # เพิ่ม cert_details แยกต่างหาก (ข้อมูลละเอียด)
        if cert_details:
            pkt_data["cert_subject"] = cert_details.get("subject", "N/A")
            pkt_data["cert_issuer"] = cert_details.get("issuer", "N/A")
            pkt_data["cert_not_before"] = cert_details.get("not_before", "N/A")
            pkt_data["cert_not_after"] = cert_details.get("not_after", "N/A")
            pkt_data["cert_san"] = cert_details.get("san", "N/A")

        if sio.connected:
            sio.emit('new_packet', pkt_data)

    except Exception as e:
        # แสดง error ใน terminal แทนที่จะกลืนเงียบ
        print(f"❌ analyze_packet error: {e}")


def start_capture(interface, bpf_filter=""):
    global stats_thread_started
    if not stats_thread_started:
        threading.Thread(target=emit_network_stats, daemon=True).start()
        stats_thread_started = True
    try:
        print(f"🚀 Starting capture on: {interface} | Filter: {bpf_filter}")
        if bpf_filter:
            sniff(iface=interface, filter=bpf_filter, prn=analyze_packet, stop_filter=lambda p: stop_event.is_set(), store=0)
        else:
            sniff(iface=interface, prn=analyze_packet, stop_filter=lambda p: stop_event.is_set(), store=0)
    except Exception as e:
        print(f"❌ Capture Error: {e}")


# --- Socket.io Events ---
@sio.on('request_interfaces')
def on_request_interfaces():
    print("📢 หน้าเว็บขอรายชื่อ Interface...")
    sio.emit('available_interfaces', get_available_ifaces())


@sio.event
def connect():
    print("✅ เชื่อมต่อสำเร็จ!")
    sio.emit('available_interfaces', get_available_ifaces())


@sio.on('control_sniffer')
def on_control(data):
    global sniff_thread
    if data['action'] == 'start':
        ip_filter = data.get('filter', '')
        print(f"เริ่มดักจับบน: {data['iface']} | IP: {ip_filter}")
        stop_event.clear()
        sniff_thread = threading.Thread(target=start_capture, args=(data['iface'], ip_filter))
        sniff_thread.start()
    elif data['action'] == 'stop':
        print("หยุดดักจับ...")
        stop_event.set()


if __name__ == '__main__':
    print("=" * 50)
    print("🛡️  PacketDukjub Sniffer (Enhanced TLS Detection)")
    print("=" * 50)
    print("🌍 Connecting to Node.js backend...")
    try:
        sio.connect('http://localhost:3000')
        sio.wait()
    except Exception as e:
        print(f"⚠️ ลืมรัน Node.js Server หรือเปล่า? Error: {e}")