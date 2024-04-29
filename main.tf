terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~>5.46"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = var.region
  # Add aws access_key and secret_key

}

#provider "vault" {
#  address = "http://localhost:8200"
#
#}
#
#
#resource "aws_iam_user" "secrets_engine" {
#  name = "${var.project_name}-user"
#}
#
#data "aws_iam_policy_document" "ec2" {
#  statement {
#    actions = ["sts:AssumeRole"]
#    principals {
#      type        = "Service"
#      identifiers = ["ec2.amazonaws.com"]
#    }
#  }
#}
#
#resource "aws_iam_policy" "session-manager" {
#  description = "session-manager"
#  name        = "session-manager"
#  policy      = jsonencode({
#    "Version":"2012-10-17",
#    "Statement":[
#      {
#        "Action": "ec2:*",
#        "Effect": "Allow",
#        "Resource": "*"
#      },
#        {
#            "Effect": "Allow",
#            "Action": "elasticloadbalancing:*",
#            "Resource": "*"
#        },
#        {
#            "Effect": "Allow",
#            "Action": "cloudwatch:*",
#            "Resource": "*"
#        },
#        {
#            "Effect": "Allow",
#            "Action": "autoscaling:*",
#            "Resource": "*"
#        },
#        {
#            "Effect": "Allow",
#            "Action": "iam:CreateServiceLinkedRole",
#            "Resource": "*",
#            "Condition": {
#                "StringEquals": {
#                    "iam:AWSServiceName": [
#                        "autoscaling.amazonaws.com",
#                        "ec2scheduled.amazonaws.com",
#                        "elasticloadbalancing.amazonaws.com",
#                        "spot.amazonaws.com",
#                        "spotfleet.amazonaws.com",
#                        "transitgateway.amazonaws.com"
#                    ]
#                }
#            }
#        }
#    ]
#  })
#}
#
#resource "aws_iam_access_key" "secrets_engine_credentials" {
#  user = aws_iam_user.secrets_engine.name
#}
#
#resource "aws_iam_role" "session-manager" {
#  assume_role_policy = data.aws_iam_policy_document.ec2.json
#  name = "session-manager"
#  tags = {
#    Name ="session-manager"
#  }
#}
#
#resource "aws_iam_instance_profile" "session-manager" {
#  name = "session-manager"
#  role = aws_iam_role.session-manager.name
#}
#resource "aws_iam_user_policy" "secrets_engine" {
#  user = aws_iam_user.secrets_engine.name
#  policy = jsonencode({
#    statement = [
#      {
#        Action = [
#          "iam:*"
#        ]
#        Effect   = "Allow"
#        Resource = "*"
#      },
#    ]
#    version = "2012-10-17"
#  })
#}
#
#resource "vault_aws_secret_backend" "aws" {
#
#  region = var.region
#  path   = "${var.project_name}_path"
#
#  access_key = aws_iam_access_key.secrets_engine_credentials.id
#  secret_key = aws_iam_access_key.secrets_engine_credentials.secret
#
#  default_lease_ttl_seconds = "120"
#}
#
#resource "vault_aws_secret_backend_role" "admin" {
#
#  backend         = vault_aws_secret_backend.aws.path
#  name            = "{var.project_name}_role"
#  credential_type = "iam_user"
#  policy_document = <<EOF
#		{
#		  "Version": "2012-10-17",
#		  "Statement": [
#			{
#				"Effect": "Allow",
#				"Action" : [
#				  "iam:*", "ec2:*","s3:*","rds:*","vpc:*"
#				 ],
#				 "Resource":"*"
#				}
#			]
#		}
#		EOF
#}


resource "aws_vpc" "main_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "Wordpress VPC"
  }
}

resource "aws_subnet" "public_subnet" {

  count             = 2
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = element(var.public_subnet_cidrs, count.index)
  availability_zone = element(var.azs, count.index)

  tags = {
    Name = "Public_Subnet_${count.index + 1}"
  }
}

resource "aws_subnet" "private_subnet_1a" {

  count             = 2
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = element(var.private_subnet_cidrs_1a, count.index)
  availability_zone = "us-east-1a"

  tags = {
    Name = "Private_Subnet_1a_${count.index + 1}"
  }
}

resource "aws_subnet" "private_subnet_1b" {

  count             = 2
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = element(var.private_subnet_cidrs_1b, count.index)
  availability_zone = "us-east-1b"

  tags = {
    Name = "Private_Subnet_1b_${count.index + 1}"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name = "Wordpress VPC IGW"
  }
}

resource "aws_eip" "nat1" {

  vpc                       = true
  associate_with_private_ip = "10.0.144.0"
  depends_on                = [aws_internet_gateway.igw]
}

resource "aws_eip" "nat2" {
  vpc                       = true
  associate_with_private_ip = "10.0.146.0"
  depends_on                = [aws_internet_gateway.igw]
}

resource "aws_nat_gateway" "nat_gateway1" {

  allocation_id = aws_eip.nat1.id
  subnet_id     = element(aws_subnet.public_subnet.*.id, 0)
  tags = {
    Name = "Wordpress_NAT1"
  }
  depends_on = [aws_eip.nat1]
}

resource "aws_nat_gateway" "nat_gateway2" {

  allocation_id = aws_eip.nat2.id
  subnet_id     = element(aws_subnet.public_subnet.*.id, 1)
  tags = {
    Name = "Wordpress_NAT2"
  }
  depends_on = [aws_eip.nat2]
}

resource "aws_route_table" "internet_rt" {

  vpc_id = aws_vpc.main_vpc.id
  tags = {
    Name = "Public-internet-rt-table"
  }
}

resource "aws_route" "public-internet-rt" {
  route_table_id         = aws_route_table.internet_rt.id
  gateway_id             = aws_internet_gateway.igw.id
  destination_cidr_block = "0.0.0.0/0"
}

resource "aws_route_table" "private_rt1" {
  vpc_id = aws_vpc.main_vpc.id
  tags = {
    Name = "Private-nat-route-1"
  }
}

resource "aws_route" "nat-rt-1" {
  route_table_id         = aws_route_table.private_rt1.id
  gateway_id             = aws_nat_gateway.nat_gateway1.id
  destination_cidr_block = "0.0.0.0/0"
}

resource "aws_route_table" "private_rt2" {
  vpc_id = aws_vpc.main_vpc.id
  tags = {
    Name = "Private-nat-route-2"
  }
}

resource "aws_route" "nat-rt-2" {
  route_table_id         = aws_route_table.private_rt2.id
  gateway_id             = aws_nat_gateway.nat_gateway2.id
  destination_cidr_block = "0.0.0.0/0"
}

resource "aws_route_table_association" "public_subnet_asso" {

  count          = length(var.public_subnet_cidrs)
  subnet_id      = element(aws_subnet.public_subnet[*].id, count.index)
  route_table_id = aws_route_table.internet_rt.id
}

resource "aws_route_table_association" "private_subnet_1a_asso" {
  route_table_id = aws_route_table.private_rt1.id
  subnet_id      = aws_subnet.private_subnet_1a[0].id
}

resource "aws_route_table_association" "private_subnet_1b_asso" {
  route_table_id = aws_route_table.private_rt2.id
  subnet_id      = aws_subnet.private_subnet_1b[0].id
}

resource "aws_security_group" "load_balancer" {
  name        = "load-balancer_sg"
  description = "Control access to the load balancer"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_subnet.private_subnet_1a[0].cidr_block, aws_subnet.private_subnet_1b[0].cidr_block]
  }
}

resource "aws_security_group" "bastion-host-sg" {
  name        = "bastion-host_security_group"
  description = "Allow inbound ssh from any where and outbound ssh into private instances."
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    # To allow ssh into bastion host.
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # To allow ssh into private instances from bastion host.
  egress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private_subnet_1a[0].cidr_block, aws_subnet.private_subnet_1b[0].cidr_block]
  }
}
resource "aws_security_group" "private_instance_SG" {
  name        = "wordpress_private_instance_sg"
  description = "Allow inbound traffic from load-balancer and outbound through NAT and allow local communication."
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.load_balancer.id]
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion-host-sg.id]
    cidr_blocks = [aws_subnet.public_subnet[0].cidr_block, aws_subnet.public_subnet[1].cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "bastion" {
  ami           = "ami-04e5276ebb8451442"
  instance_type = "t2.micro"
  key_name      = aws_key_pair.wordpress.key_name
  #  iam_instance_profile = aws_iam_instance_profile.session-manager.id
  associate_public_ip_address = true
  security_groups             = [aws_security_group.bastion-host-sg.id]
  subnet_id                   = aws_subnet.public_subnet[0].id
  provisioner "local-exec" {
    command = "echo '${tls_private_key.bastion.private_key_pem}' > ./private1_key.pem"
  }
  user_data = <<-EOF
      sudo yum update -y
  EOF
  tags = {
    Name = "Bastion"
  }
}

resource "aws_instance" "private_instance_1a" {
  ami             = "ami-04e5276ebb8451442"
  instance_type   = "t2.micro"
  security_groups = [aws_security_group.private_instance_SG.id]
  subnet_id       = aws_subnet.private_subnet_1a[0].id
  user_data       = <<-EOF
              #!/bin/bash
              sudo yum update -y
              sudo yum install docker -y
              sudo service docker start
              sudo chmod 666 /var/run/docker.sock
              docker pull nginx
              docker tag nginx my-nginx
              docker run --rm --name nginx-server -d -p 80:80 -t my-nginx
              EOF

  tags = {
    Name = "Wordpress_instance_private_1a"
  }
}

resource "aws_instance" "private_instance_1b" {
  ami             = "ami-04e5276ebb8451442"
  instance_type   = "t2.micro"
  security_groups = [aws_security_group.private_instance_SG.id]
  subnet_id       = aws_subnet.private_subnet_1b[0].id
  key_name = aws_key_pair.wordpress.key_name
  user_data       = <<-EOF
              #!/bin/bash
              sudo yum update -y
              sudo yum install docker -y
              sudo service docker start
              sudo chmod 666 /var/run/docker.sock
              docker pull nginx
              docker tag nginx my-nginx
              docker run --rm --name nginx-server -d -p 80:80 -t my-nginx
              EOF

  tags = {
    Name = "Wordpress_instance_private_1b"
  }
  depends_on = [aws_key_pair.wordpress]
}

resource "aws_alb" "wordpress-lb" {
  name               = "wordpress-lb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.load_balancer.id, aws_security_group.bastion-host-sg.id]
  subnets            = [aws_subnet.private_subnet_1b[0].id, aws_subnet.private_subnet_1a[0].id]
}

resource "aws_alb_target_group" "wordpress-tg" {
  name        = "wordpress-tg"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.main_vpc.id

  health_check {
    path                = "/"
    port                = "traffic-port"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 60
    matcher             = "200"
  }
}

#resource "aws_alb_target_group_attachment" "wordpress" {
#  target_group_arn = aws_alb_target_group.wordpress-tg.arn
#  target_id        = aws_autoscaling_group.ec2_cluster.
#  depends_on       = [aws_alb_target_group.wordpress-tg]
#}

resource "aws_alb_listener" "ec2_alb_listener" {
  load_balancer_arn = aws_alb.wordpress-lb.arn
  port              = "80"
  protocol          = "HTTP"
  depends_on        = [aws_alb_target_group.wordpress-tg]

  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.wordpress-tg.arn
  }
}
resource "aws_autoscaling_group" "ec2_cluster" {
  name                 = "wordpress_auto_scaling"
  min_size             = var.autoscale_min
  max_size             = var.autoscale_max
  desired_capacity     = var.autoscale_desired
  health_check_type    = "EC2"
  launch_configuration = aws_launch_configuration.wordpress_lb_launch_config.name
  vpc_zone_identifier  = [aws_subnet.private_subnet_1a[0].id, aws_subnet.private_subnet_1b[0].id]
  target_group_arns    = [aws_alb_target_group.wordpress-tg.arn]
}

resource "aws_key_pair" "wordpress" {
  public_key = tls_private_key.bastion.public_key_openssh
  key_name   = "wordpress_kp"
  provisioner "local-exec" {
    command = "echo '${tls_private_key.bastion.private_key_pem}' > ./private1_key.pem"
  }
}

resource "tls_private_key" "bastion" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_launch_configuration" "wordpress_lb_launch_config" {
  name_prefix     = "wordpress_instance"
  image_id        = var.launch_config_ec2_ami
  instance_type   = "t2.micro"
  security_groups = [aws_security_group.private_instance_SG.id]
  key_name        = aws_key_pair.wordpress.key_name
  #  iam_instance_profile = aws_iam_instance_profile.session-manager.id
  associate_public_ip_address = false
  user_data                   = <<-EOL
  #!/bin/bash
  sudo yum -y update
  sudo yum install -y docker
  sudo service docker start
  sudo chmod 666 /var/run/docker.sock
  docker pull nginx
  docker tag nginx my-nginx
  docker run --rm --name nginx-server -d -p 80:80 -t my-nginx
  EOL
  depends_on                  = [aws_nat_gateway.nat_gateway1, aws_nat_gateway.nat_gateway2]
}

resource "aws_s3_bucket" "wordpressbucket1431797test" {
  bucket = "wordpressbucket1431797test"
  acl    = "private"
  versioning {
    enabled = true
  }
}

resource "aws_cloudfront_distribution" "wordpress_cloudfront" {
  origin {
    domain_name = aws_s3_bucket.wordpressbucket1431797test.bucket_regional_domain_name
    origin_id   = "S3Origin"
  }

  enabled = true

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3Origin"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
