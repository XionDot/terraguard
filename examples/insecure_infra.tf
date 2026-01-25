provider "aws" {
  region = "us-east-1"
  # BAD: Hardcoded credentials - secrets scanner will flag this
  # access_key = "AKIAIOSFODNN7EXAMPLE"
  # secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.2xlarge"

  vpc_security_group_ids = [aws_security_group.web.id]

  root_block_device {
    volume_size = 500
    encrypted   = false
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-bucket"
}

resource "aws_db_instance" "main" {
  identifier          = "prod-database"
  engine              = "mysql"
  instance_class      = "db.r5.4xlarge"
  allocated_storage   = 1000
  username            = "admin"
  password            = "SuperSecret123!"
  publicly_accessible = true
  skip_final_snapshot = true
}
