resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
}

resource "aws_s3_bucket_acl" "public_bucket_acl" {
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "public-read"
}

resource "aws_security_group" "open_db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "exposed_db" {
  engine               = "postgres"
  publicly_accessible  = true
  username             = "admin"
}
