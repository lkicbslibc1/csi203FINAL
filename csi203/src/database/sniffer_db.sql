-- phpMyAdmin SQL Dump
-- version 5.2.3
-- https://www.phpmyadmin.net/
--
-- Host: db
-- Generation Time: Apr 07, 2026 at 05:05 PM
-- Server version: 8.0.45
-- PHP Version: 8.3.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `sniffer_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `packets`
--

CREATE TABLE `packets` (
  `id` int NOT NULL,
  `protocol` varchar(20) DEFAULT NULL,
  `src` varchar(50) DEFAULT NULL,
  `dst` varchar(50) DEFAULT NULL,
  `port` int DEFAULT NULL,
  `size` int DEFAULT NULL,
  `encryption` varchar(20) DEFAULT NULL,
  `cipher` varchar(255) DEFAULT NULL,
  `cert` text,
  `tls_version` varchar(20) DEFAULT NULL,
  `handshake_type` varchar(50) DEFAULT NULL,
  `payload` text,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `users_id` int DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `packets`
--
-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` varchar(20) NOT NULL,
  `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `role`, `createdAt`) VALUES
(1, 'map', '$2b$10$2wnikGYLUZbNXtvRTAWLE.LWMZsNz8F4IASSJbqtVPP/ZzWjvFOQ6', 'admin', '2026-04-07 11:20:28'),
(2, 't', '$2b$10$XgkeglGobjLWlILiEsEU.uXZ0RjXCCi7TFTc6nQbPAKG3g45WvU4W', 'user', '2026-04-07 11:29:13'),
(6, 'oshi', '$2b$10$6jVXuc/aXk1JnQO.3golIOm6fdjMv8nd2k0jGO0J9PWXHZizSS0li', 'user', '2026-04-07 15:52:34');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `packets`
--
ALTER TABLE `packets`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `packets`
--
ALTER TABLE `packets`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=62999;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
