# Three-tier web app: the canonical fixture for the Helios test suite.
# Intentionally small. Exercises all 8 resource types helios-graph v0.1 parses.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags       = { Name = "three-tier-webapp" }
}

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.main.id
  availability_zone = "us-east-1a"
  cidr_block        = "10.0.1.0/24"
}

resource "aws_subnet" "public_b" {
  vpc_id            = aws_vpc.main.id
  availability_zone = "us-east-1b"
  cidr_block        = "10.0.2.0/24"
}

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public_a.id
}

resource "aws_lb" "app" {
  name               = "three-tier-alb"
  load_balancer_type = "application"
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]
}

resource "aws_db_instance" "primary" {
  identifier           = "three-tier-db"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "changeme-in-real-life"
  multi_az             = true
  db_subnet_group_name = "three-tier-db-subnets"
  skip_final_snapshot  = true
}

resource "aws_elasticache_cluster" "cache" {
  cluster_id         = "three-tier-cache"
  engine             = "redis"
  node_type          = "cache.t3.micro"
  num_cache_nodes    = 1
  subnet_group_name  = "three-tier-cache-subnets"
}

resource "aws_lambda_function" "worker" {
  function_name = "three-tier-worker"
  role          = "arn:aws:iam::123456789012:role/lambda-worker"
  handler       = "index.handler"
  runtime       = "python3.12"
  vpc_config {
    subnet_ids         = [aws_subnet.public_a.id, aws_subnet.public_b.id]
    security_group_ids = []
  }
}

resource "aws_s3_bucket" "assets" {
  bucket = "three-tier-webapp-assets-unique"
}
