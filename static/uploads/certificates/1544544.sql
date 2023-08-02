-- MySQL dump 10.13  Distrib 8.0.34, for Win64 (x86_64)
--
-- Host: localhost    Database: doctors
-- ------------------------------------------------------
-- Server version	8.0.34

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `game`
--

DROP TABLE IF EXISTS `game`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `game` (
  `ID` int DEFAULT NULL,
  `GAME` enum('ATHLETICS','ARCHERY','BADMINTON','CARROM','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLETENNIS','LAWNTENNIS','CRICKET_WHITE_BALL','HARD_TENNIS_CRICKET','WOMEN_BOX_CRICKET','VOLLEYBALL','FOOTBALL','KHO KHO','KABADDI','THROW BALL','TUG_OF_WAR') DEFAULT NULL,
  `AMOUNT` int unsigned DEFAULT NULL,
  KEY `ID` (`ID`),
  CONSTRAINT `game_ibfk_1` FOREIGN KEY (`ID`) REFERENCES `register` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `game`
--

LOCK TABLES `game` WRITE;
/*!40000 ALTER TABLE `game` DISABLE KEYS */;
INSERT INTO `game` VALUES (230013,'ATHLETICS',3500),(230016,'CYCLOTHON',3500);
/*!40000 ALTER TABLE `game` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `games`
--

DROP TABLE IF EXISTS `games`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `games` (
  `game_name` varchar(30) DEFAULT NULL,
  `amount` int unsigned DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `games`
--

LOCK TABLES `games` WRITE;
/*!40000 ALTER TABLE `games` DISABLE KEYS */;
INSERT INTO `games` VALUES ('ATHLETICS',1500),('ARCHERY',1500),('BADMINTON',10000),('BASKET_BALL',10000),('CARROM',1500),('CHESS',1500),('CYCLOTHON',1500),('JUMPS',1500),('WALKATHON',1500),('SWIMMING',1500),('THROW',1500),('ROWING',1500),('ROLLER_SKATING',1500),('FENCING',1500),('TENNIKOIT',1500),('TABELTENNIS',1500),('LAWNTENNIS',1500),('BALL_BADMINTON',10000),('CRICKET_WHITE_BALL',30000),('HARD_TENNIS_CRICKET',20000),('WOMEN_BOX_CRICKET',10000),('VOLLEYBALL',10000),('FOOTBALL',10000),('KHO_KHO',10000),('KABADDI',10000),('THROW_BALL',10000),('TUG_OF_WAR',5000);
/*!40000 ALTER TABLE `games` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `payments`
--

DROP TABLE IF EXISTS `payments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `payments` (
  `ordid` binary(16) NOT NULL,
  `id` int DEFAULT NULL,
  `game` enum('ATHLETICS','ARCHERY','BADMINTON','CARROM','CHESS','CYCLOTHON','JUMPS','WALKATHON','SWIMMING','TENNKOIT','THROW','ROWING','ROLLER SKATING','FENCING','SHOOTING','TABLE TENNIS','LAWN TENNIS') DEFAULT NULL,
  `amount` int unsigned DEFAULT NULL,
  `date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`ordid`),
  KEY `id` (`id`),
  CONSTRAINT `payments_ibfk_1` FOREIGN KEY (`id`) REFERENCES `register` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `payments`
--

LOCK TABLES `payments` WRITE;
/*!40000 ALTER TABLE `payments` DISABLE KEYS */;
/*!40000 ALTER TABLE `payments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `register`
--

DROP TABLE IF EXISTS `register`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `register` (
  `ID` int NOT NULL AUTO_INCREMENT,
  `FirstName` varchar(25) DEFAULT NULL,
  `LastName` varchar(25) DEFAULT NULL,
  `Email` varchar(50) DEFAULT NULL,
  `PASSWORD` longblob,
  `mobileno` bigint DEFAULT NULL,
  `age` int DEFAULT NULL,
  `gender` varchar(10) DEFAULT NULL,
  `DOB` date DEFAULT NULL,
  `city` text,
  `address` text,
  `state` text,
  `country` text,
  `degree` varchar(10) DEFAULT NULL,
  `MCI_ID` varchar(20) DEFAULT NULL,
  `member` varchar(20) DEFAULT NULL,
  `SHIRT_SIZE` enum('S','M','L','XL','XXL','XXXL','XXXXL') DEFAULT NULL,
  `acception` varchar(30) DEFAULT 'No',
  `status` varchar(20) NOT NULL DEFAULT 'pending',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `Email` (`Email`),
  UNIQUE KEY `mobileno` (`mobileno`)
) ENGINE=InnoDB AUTO_INCREMENT=230017 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `register`
--

LOCK TABLES `register` WRITE;
/*!40000 ALTER TABLE `register` DISABLE KEYS */;
INSERT INTO `register` VALUES (230013,'check','someone','diarysilk68@gmail.com',_binary '$2b$12$FpoM2ECD8B8K.pmC0RAocOMQ7uMGn5EuPWX0HtymUgeHDA/FBVcna',9014626272,18,'Male','2023-07-21','vijayawada','poranki','Andhra Pradesh','Egypt','MD','mt26523hsdf','IMA Member','XXL','Yes','success'),(230016,'Tony','Stark','dvin3226@gmail.com',_binary '$2b$12$VV.gCIwMey0rW9TJIHypB.AUy3FVxrzQ/Hf2RIXr3bnjyvy6WHt.i',9014626273,23,'Male','2023-07-10','vijayawada','vijayawada','Andhra Pradesh','India','MBBS','sds3243er','IMA Member','XL','Yes','success');
/*!40000 ALTER TABLE `register` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2023-07-29 19:23:09
