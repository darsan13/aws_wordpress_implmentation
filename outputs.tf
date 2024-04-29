
output "vpc_id" {

  description = "ID of the wordpress VPC"
  value       = aws_vpc.main_vpc.id
}


output "public_subnet_cidr" {

  description = "CIDR range of public subnets in wordpress VPC"
  value = {
    for subnet in aws_subnet.public_subnet :
    subnet.id => subnet.cidr_block
  }
}

output "private_subnet_1a_cidr" {

  description = "CIDR block of private subnets in wordpress VPC"

  value = {
    for subnet in aws_subnet.private_subnet_1a :
    subnet.id => subnet.cidr_block
  }
}

output "private_subnet_1b_cidr" {

  description = "CIDR block of private subnets in wordpress VPC 1b AZ"

  value = {
    for subnet in aws_subnet.private_subnet_1b :
    subnet.id => subnet.cidr_block
  }
}

output "loadbalancer_dns" {
  description = "DNS of the load balancer"

  value = aws_alb.wordpress-lb.dns_name
}


