# Infrastructure as a Code on AWS Platform using Terraform

## Tier 3 Application Design 

![Tier-3 Architecture](https://github.com/dineshsparab/testproject/blob/master/awstier3.PNG)

## Design Considerations

***This Architecture is designed specifically for One Region and setup in Two Availability Zones**

***This Tier-3 Architecture is designed to host Secured SSL based Web Application which is using cluster based PostgresSQL intance as a Backend**

***It uses Two Elastic Load Balancers (ELBs) across two Availability Zones in Public Subnet to distribute inbound traffic to Web Servers**

***Public Subnet has two NAT g/ws for secured outbound communication from WebServer to Internet**

**VPC has below components**

	*Internet G/w
	*Route Tables
	*NAT G/ws
	*Web, App & DB Subnets

***Web Server and App Server are on AutoScaling Group with AutoScaling Policy for Vertical Scaling (Additional CPUs)**

***DB Server is PostgreSQL RDS Cluster Instance with Read Replica across Availability Zone**

Below Components are developed using Terraform Code

___
#

|Sr.No|Component|Remarks|
|-----|-------- |----------|
| 1 |  Certificate Import|SSL Certificate Import Code|
| 2 |  Certificate Create|SSL Certificate creation and register in ACM|
| 3 |  IAM|Create Users and Roles|
| 4 |  VPC|Create VPC, IGW, Route Tables, Subnets|
| 5 |  Security Group|Create Ingress and Igress rules|
| 6 |  ELB|Create Elastic Load Balancers across Availability Zones|
| 7 |  Front End|WebServer AutoScaling|
| 8 |  Application Layer|Application Server AutoScaling|
| 9 |  Database Layer|PostgreSQL Cluster Instance|
|10 |  Storage|S3 Bucket|
#
___

	
	
# SSL Certificate Create / Import

## SSL Certificate flow Chart

![SSL Certificate create/import](https://github.com/dineshsparab/testproject/blob/master/SSL_Cert.PNG)

## ## Terraform Code file name - cert-import.tf

```Terraform

#Certificate Import#################################################################
resource "tls_private_key" "dev" {
  algorithm = "RSA"
}

resource "tls_self_signed_cert" "dev" {
  key_algorithm   = "RSA"
  private_key_pem = tls_private_key.dev.private_key_pem

  subject {
    common_name  = var.domain_name
   #organization = "dev corp"
  }

  validity_period_hours = 12

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "aws_acm_certificate" "certificate" {
  private_key      =  tls_private_key.dev.private_key_pem
  certificate_body =  tls_self_signed_cert.dev.cert_pem
}
```
___

## Terraform Code file name - cert-create.tf

```Terraform

# Create Certificate#####################################################################
resource "aws_acm_certificate" "cert" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# Route53 DNS Zone######################################################################
 data "aws_route53_zone" "public" {
  name         = var.domain_name
  private_zone = false
}

# Cert record ######################################################################
resource "aws_route53_record" "cert_rec" {
  count   = length(var.domain_name)

  name    = aws_acm_certificate.cert.domain_validation_options[count.index].resource_record_name
  type    = aws_acm_certificate.cert.domain_validation_options[count.index].resource_record_type
  zone_id = var.zone_id
  records = [aws_acm_certificate.cert.domain_validation_options[count.index].resource_record_value]
  ttl     = 60
}

# Certificate Validation######################################################################
resource "aws_acm_certificate_validation" "cert" {
  certificate_arn         = aws_acm_certificate.cert.arn
  validation_record_fqdns = aws_route53_record.cert_rec.*.fqdn
}
# Provides an IAM Server Certificate resource to upload Server Certificates.
resource "aws_iam_server_certificate" "test_cert" {
  name             = "test_cert"
  certificate_body =  file("self-ca-cert.pem")
  private_key      =  file("test-key.pem")
} 

```
___

## Attaching SSL Certificate to ELBs

### Terraform Code file name - elb-cert.tf


```Terraform
resource "aws_alb_listener" "web-elb-az1" {
	load_balancer_arn	    =	aws_elb.web-elb-az1.arn
	port			            =	"443"
	protocol		          =	"HTTPS"
	ssl_policy		        =	var.ssl_policy
	certificate_arn		    =	aws_iam_server_certificate.test_cert.arn

	default_action {
		target_group_arn	=	aws_iam_server_certificate.test_cert.arn
		type			    =	"forward"
	}
}

resource "aws_alb_listener" "web-elb-az2" {
	load_balancer_arn	    =	aws_elb.web-elb-az2.arn
	port			            =	"443"
	protocol		          =	"HTTPS"
	ssl_policy		        =	var.ssl_policy
	certificate_arn		    =	aws_iam_server_certificate.test_cert.arn

	default_action {
		target_group_arn	=	aws_iam_server_certificate.test_cert.arn
		type			    =	"forward"
	}
}

```
___

# Creating Users and Roles

## IAM users

### Terraform Code file name - iam.tf

```Terraform

# Group 1 - Admin Group for Managing all resources within subscription (Administrator)

resource "aws_iam_group" "admin_group" {
  name = "admin_group"
  path = "/users/"
}
resource "aws_iam_group_policy" "admin_policy" {
  name  = "admin_policy"
  group = aws_iam_group.admin_group.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "*",
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
# Group 2 - Monitoring Group for Resource monitoring (PowerUser)

resource "aws_iam_group" "app_group" {
  name = "app_group"
  path = "/users/"
}
resource "aws_iam_group_policy" "app_policy" {
  name  = "app_policy"
  group =  aws_iam_group.app_group.id

policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:v100*",
                "ec2:v100*",
                "ec2:RebootInstances",
                "ec2:StopInstances",
                "ec2:TerminateInstances"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

#Creation of User - Admin & Apps Users
resource "aws_iam_user" "admin" {
  name = "admin"
  path = "/system/"

  tags = {
    tag-key = "admin user"
  }
}

resource "aws_iam_user" "user1" {
  name = var.user_name1
  path = "/system/"

  tags = {
    tag-key = "Application User - 1"
  }
}
/*
resource "aws_iam_user" "user2" {
  name = "user2"
  path = "/system/"

  tags = {
    tag-key = "Application User - 2"
  }
}
*/

# Admin Group Membership association

resource "aws_iam_group_membership" "admin-members" {
  name = "admin group members"

  users = [
    "${aws_iam_user.admin.name}",
  ]

  group = aws_iam_group.admin_group.name
}

# App Group Membership association

resource "aws_iam_group_membership" "app-members" {
  name = "app group members"

  users = [
    "${aws_iam_user.user1.name}",
  #  "${aws_iam_user.user2.name}",

  ]

  group = aws_iam_group.app_group.name
}
```
___


## IAM EC2 Role

### Terraform Code file name - roles.tf


```Terraform

#EC2 role for EC2 v100 Instance access to All resources

resource "aws_iam_role_policy" "ec2_policy" {
  name = "ec2_policy"
  role = aws_iam_role.ec2_role.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "ec2:*"
        ],
        "Effect": "Allow",
        "Resource": "*"
      }
    ]
  }
  EOF
}

resource "aws_iam_role" "ec2_role" {
  name = "ec2_role"

  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  }
  EOF
}

```
___


# VPC

![VPC - Tier-3](https://github.com/dineshsparab/testproject/blob/master/vpc.PNG)

## Creation of Internet Gateway / NAT Gateway

### Terraform Code file name - vpc.tf

```Terraform

resource "aws_vpc" "v100vpcr" {
  cidr_block       		  = var.vpccidr
  instance_tenancy      = var.instanceTenancy 
  enable_dns_support    = true
  enable_dns_hostnames  = true

  tags = {
    Name = "My v100 main VPC"
  }
}

# Create the Internet Gateway************
resource "aws_internet_gateway" "v100igwr" {
 vpc_id = aws_vpc.v100vpcr.id
 tags = {
        Name = "My v100 VPC Internet Gateway"
 }
} # end resource

# Create the Route Table***************

resource "aws_route_table" "v100rbtlr" {
 vpc_id = aws_vpc.v100vpcr.id
 tags = {
        Name = "My v100 VPC Route Table"
}
} # end resource

resource "aws_route_table" "v100prt1" {
 vpc_id = aws_vpc.v100vpcr.id
 tags = {
        Name = "My v100 Private 1 Route Table"
}
} # end resource

resource "aws_route_table" "v100prt2" {
 vpc_id = aws_vpc.v100vpcr.id
 tags = {
        Name = "My v100 Private 2 Route Table"
}
} # end resource



# Create the Internet Access**************
resource "aws_route" "v100vpcr_internet_access" {
  route_table_id         = aws_route_table.v100rbtlr.id
  destination_cidr_block = var.destinationCIDRblock
  gateway_id             = aws_internet_gateway.v100igwr.id
} # end resource

resource "aws_eip" "v100NAT1" {
    vpc = true
}

resource "aws_nat_gateway" "v100NAT-gw1" {
  allocation_id = aws_eip.v100NAT1.id
  subnet_id     = aws_subnet.v100sntpubaz1.id

  tags = {
    Name = "V100 NAT GW1"
  }
}
resource "aws_route" "NAT1_internet_access" {
  route_table_id         = aws_route_table.v100prt1.id
  destination_cidr_block = var.destinationCIDRblock
  gateway_id             = aws_internet_gateway.v100igwr.id
} # end resource

resource "aws_eip" "v100NAT2" {
    vpc = true
}
resource "aws_nat_gateway" "v100NAT-gw2" {
  allocation_id = aws_eip.v100NAT2.id
  subnet_id     = aws_subnet.v100sntpubaz2.id

  tags = {
    Name = "V100 NAT GW2"
  }
}

resource "aws_route" "NAT2_internet_access" {
  route_table_id         = aws_route_table.v100prt2.id
  destination_cidr_block = var.destinationCIDRblock
  gateway_id             = aws_internet_gateway.v100igwr.id
} # end resource

```

## Creation of Public/Private Subnets with Route Tables

### Terraform Code file name - vpc.tf

```Terraform

########## Public subnet ###########

resource "aws_subnet" "v100sntpubaz1" {
  vpc_id                  = aws_vpc.v100vpcr.id
  cidr_block              = var.public_subnet_AZ1
  availability_zone       = var.AZ_1
 tags = {
   Name = "My v100 Public Subnet AZ1"
 }
} # end resource

resource "aws_subnet" "v100sntpubaz2" {
  vpc_id                  = aws_vpc.v100vpcr.id
  cidr_block              = var.public_subnet_AZ2
  availability_zone       = var.AZ_2
 tags = {
   Name = "My v100 Public Subnet AZ2"
 }
} # end resource


############ Web Subnet Availability Zone 1 & Availability Zone 2 #########

# create the Private Subnet Availability Zone 1
resource "aws_subnet" "v100sntwebaz1" {
  vpc_id                  = aws_vpc.v100vpcr.id
  cidr_block              = var.web_subnet_AZ1
  availability_zone       = var.AZ_1
 tags = {
   Name = "My v100 WEB Subnet AZ1"
 }
} # end resource

# create the Private Subnet Availability Zone 2
resource "aws_subnet" "v100sntwebaz2" {
  vpc_id                  = aws_vpc.v100vpcr.id
  cidr_block              = var.web_subnet_AZ2
  availability_zone       = var.AZ_2
 tags = {
   Name = "My v100 WEB Subnet AZ2"
  }
} # end resource

############ APP Subnet Availability Zone 1 & Availability Zone 2 #########

# create the Public Subnet Availability Zone 1
resource "aws_subnet" "v100sntappaz1" {
  vpc_id                  = aws_vpc.v100vpcr.id
  cidr_block              = var.app_subnet_AZ1
  availability_zone       = var.AZ_1
 tags = {
   Name = "My v100 APP Subnet AZ1"
 }
} # end resource

# create the Public Subnet Availability Zone 2
resource "aws_subnet" "v100sntappaz2" {
  vpc_id                  = aws_vpc.v100vpcr.id
  cidr_block              = var.app_subnet_AZ2
  availability_zone       = var.AZ_2
 tags = {
   Name = "My v100 APP Subnet AZ2"
 }
} # end resource

############ DB Subnet Availability Zone 1 & Availability Zone 2 #########
# create the Public Subnet Availability Zone 1
resource "aws_subnet" "v100sntdbaz1" {
  vpc_id                  = aws_vpc.v100vpcr.id
  cidr_block              = var.db_subnet_AZ1
  availability_zone       = var.AZ_1
 tags = {
   Name = "My v100 DB Subnet AZ1"
 }
} # end resource

# create the Public Subnet Availability Zone 2
resource "aws_subnet" "v100sntdbaz2" {
  vpc_id                  = aws_vpc.v100vpcr.id
  cidr_block              = var.db_subnet_AZ2
  availability_zone       = var.AZ_2
 tags = {
   Name = "My v100 DB Subnet AZ2"
 }
} # end resource

#resource "aws_db_subnet_group" "v100DBGRP" {
#  name       = "main"
#  subnet_ids = ["${aws_subnet.v100sntdbaz1.id}", "${aws_subnet.v100sntdbaz2.id}"]

#  tags = {
#    Name = "My v100 DB subnet group"
#  }
#}
######### Associate the Route Table with the Private Subnet ##########
resource "aws_route_table_association" "webAZ1"{
  subnet_id      = aws_subnet.v100sntwebaz1.id
  route_table_id = aws_route_table.v100prt1.id
} # end resource

resource "aws_route_table_association" "webAZ2"{
  subnet_id      = aws_subnet.v100sntwebaz2.id
  route_table_id = aws_route_table.v100prt2.id
} # end resource

resource "aws_route_table_association" "appAZ1"{
  subnet_id      = aws_subnet.v100sntappaz1.id
  route_table_id = aws_route_table.v100prt1.id
} # end resource

resource "aws_route_table_association" "appAZ2"{
  subnet_id      = aws_subnet.v100sntappaz2.id
  route_table_id = aws_route_table.v100prt2.id
} # end resource
resource "aws_route_table_association" "dbAZ1"{
  subnet_id      = aws_subnet.v100sntdbaz1.id
  route_table_id = aws_route_table.v100prt1.id
} # end resource

resource "aws_route_table_association" "dbAZ2"{
  subnet_id      = aws_subnet.v100sntdbaz2.id
  route_table_id = aws_route_table.v100prt2.id
} # end resource

```
___

# Elastic Load Balancers

## Creation of First ELB

### Terraform Code file name - elb1.tf


```Terraform

resource "aws_elb" "web-elb-az1" {
  name = "v100web-elb-az1"
  security_groups = ["${aws_security_group.elb-http-az1.id}"]
  subnets = ["${aws_subnet.v100sntwebaz1.id}", "${aws_subnet.v100sntwebaz2.id}"]
  cross_zone_load_balancing   = true
  health_check {
    healthy_threshold = 2
    unhealthy_threshold = 2
    timeout = 3
    interval = 30
    target = "HTTP:80/"
  }
  listener {
    lb_port = 80
    lb_protocol = "http"
    instance_port = "80"
    instance_protocol = "http"
  }
  
}

```
___

## Creation of Second ELB

### Terraform Code file name - elb2.tf

```Terraform

resource "aws_elb" "web-elb-az2" {
  name = "v100web-elb-az2"
  security_groups = ["${aws_security_group.elb-http-az2.id}" ]
  subnets = ["${aws_subnet.v100sntwebaz2.id}", "${aws_subnet.v100sntwebaz1.id}"]
  cross_zone_load_balancing   = true
  health_check {
    healthy_threshold = 2
    unhealthy_threshold = 2
    timeout = 3
    interval = 30
    target = "HTTP:80/"
  }
  listener {
    lb_port = 80
    lb_protocol = "http"
    instance_port = "80"
    instance_protocol = "http"
  }
  
}

```




___

# Web Server Autoscaling

![Web Server AutoScaling](https://github.com/dineshsparab/testproject/blob/master/webautoscale.PNG)

## Creation WebServer Autoscale Group

### Terraform Code file name - webautoscaling.tf

```Terraform

############################### Auto scaling and launch_configuration of Web Servers  ######################################
resource "aws_launch_configuration" "lc_web" {
  name_prefix = "web-"
  image_id = "ami-06a46da680048c8ae"
  instance_type = "t2.micro"
  key_name = "v100ddhjpkey_linuxz"
  security_groups = ["${aws_security_group.v100sg-webr.id}"]
  #associate_public_ip_address = true

  lifecycle {
    create_before_destroy = true
  }
# Required to redeploy without an outage.

/*  tags {
		key                 = "Name"
		value               = "lc_web"
		propagate_at_launch = "true"
  }
 */ 
}

resource "aws_autoscaling_group" "web-asg" {
  name = "web-asg"

  min_size             = 1
  desired_capacity     = 2
  max_size             = 4

  health_check_type    = "ELB"
  load_balancers= ["${aws_elb.web-elb-az1.id}","${aws_elb.web-elb-az2.id}"]

  launch_configuration = aws_launch_configuration.lc_web.id
  
  # Below availability zone was conflicting with VPC zone identifier hence commented it
  #availability_zones = ["ap-northeast-1a", "ap-northeast-1c"]

  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupTotalInstances"
  ]

  metrics_granularity="1Minute"

  vpc_zone_identifier  = ["${aws_subnet.v100sntwebaz1.id}", "${aws_subnet.v100sntwebaz2.id}"]

}

```

___


## Creation WebServer Autoscale Policy

### Terraform Code file name - webautoscalingpolicy.tf


```Terraform

##################### Web Auto scaling policy #########################

resource "aws_autoscaling_policy" "web-policy-up" {
  name = "web-policy-up"
  scaling_adjustment = 1
  adjustment_type = "ChangeInCapacity"
  cooldown = 300
  autoscaling_group_name = aws_autoscaling_group.web-asg.name
}

resource "aws_cloudwatch_metric_alarm" "web_cpu_alarm_up" {
  alarm_name = "web_cpu_alarm_up"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "2"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "120"
  statistic = "Average"
  threshold = "80"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.web-asg.name
  }

  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions = ["${aws_autoscaling_policy.web-policy-up.arn}"]
}

resource "aws_autoscaling_policy" "web_policy_down" {
  name = "web_policy_down"
  scaling_adjustment = -1
  adjustment_type = "ChangeInCapacity"
  cooldown = 300
  autoscaling_group_name = aws_autoscaling_group.web-asg.name
}

resource "aws_cloudwatch_metric_alarm" "web_cpu_alarm_down" {
  alarm_name = "web_cpu_alarm_down"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods = "2"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "120"
  statistic = "Average"
  threshold = "40"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.web-asg.name
  }

  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions = ["${aws_autoscaling_policy.web_policy_down.arn}"]
}

```

___

# Application Server Autoscaling

![App Server AutoScaling](https://github.com/dineshsparab/testproject/blob/master/appautoscale.PNG)

## Creation AppServer Autoscale Group

### Terraform Code file name - appautoscaling.tf


```Terraform

############################### Auto scaling and launch_configuration of Application Servers  ######################################
resource "aws_launch_configuration" "lc_app" {
  name_prefix = "app-"
  image_id = "ami-06a46da680048c8ae"
  instance_type = "t2.micro"
  key_name = "v100ddhjpkey_linuxz"
  security_groups = ["${aws_security_group.v100sg-appr.id}"]

  lifecycle {
    create_before_destroy = true
  }
# Required to redeploy without an outage.
  /*
  tags {
		key                 = "Name"
		value               = "lc_app"
		propagate_at_launch = "true"
  }
  */
}

resource "aws_autoscaling_group" "app-asg" {
  name = "app-asg"

  min_size             = 1
  desired_capacity     = 2
  max_size             = 4  

  launch_configuration = aws_launch_configuration.lc_app.id
  
  # Below availability zone was conflicting with VPC zone identifier hence commented it
  #availability_zones = ["ap-northeast-1a", "ap-northeast-1c"]

  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupTotalInstances"
  ]

  metrics_granularity="1Minute"

  vpc_zone_identifier  = ["${aws_subnet.v100sntappaz1.id}", "${aws_subnet.v100sntappaz2.id}" ]
 
}

```
___


## Creation AppServer Autoscale Policy

### Terraform Code file name - appautoscalingpolicy.tf

```Terraform

##################### Application Auto scaling policy #########################
resource "aws_autoscaling_policy" "app-policy-up" {
  name = "app-policy-up"
  scaling_adjustment = 1
  adjustment_type = "ChangeInCapacity"
  cooldown = 300
  autoscaling_group_name = aws_autoscaling_group.app-asg.name
}

resource "aws_cloudwatch_metric_alarm" "app_cpu_alarm_up" {
  alarm_name = "app_cpu_alarm_up"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "2"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "120"
  statistic = "Average"
  threshold = "80"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app-asg.name
  }

  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions = ["${aws_autoscaling_policy.app-policy-up.arn}"]
}

resource "aws_autoscaling_policy" "app-policy-down" {
  name = "app-policy-down"
  scaling_adjustment = -1
  adjustment_type = "ChangeInCapacity"
  cooldown = 300
  autoscaling_group_name = aws_autoscaling_group.app-asg.name
}

resource "aws_cloudwatch_metric_alarm" "app_cpu_alarm_down" {
  alarm_name = "app_cpu_alarm_down"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods = "2"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "120"
  statistic = "Average"
  threshold = "40"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app-asg.name
  }

  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions = ["${aws_autoscaling_policy.app-policy-down.arn}"]
}

```

___


# RDS - Relational Database Services - Cluster 

![RDS Cluster](https://github.com/dineshsparab/testproject/blob/master/rdscluster.PNG)

## Creation RDS Cluster Services

### Terraform Code file name - main.tf

```Terraform

locals {
  port                       = var.port == "" ? var.engine == "aurora-postgresql" ? "5432" : "3306" : var.port
  master_password            = var.password == "" ? random_id.master_password.b64 : var.password
  create_enhanced_monitoring = var.create_resources && var.monitoring_interval > 0 ? true : false
  cluster_instance_count     = var.create_resources ? var.replica_autoscaling ? var.replica_scale_min : var.replica_count : 0
}

# Random string to use as master password unless one is specified
resource "random_id" "master_password" {
  byte_length = 10
}

resource "aws_db_subnet_group" "main" {
  count       = var.create_resources ? 1 : 0
  name        = var.name
  description = "For Aurora cluster ${var.name}"
  subnet_ids  = var.subnet_ids
  tags = merge(
    var.tags,
    {
      "Name" = "aurora-${var.name}"
    },
  )
}

resource "aws_rds_cluster" "main" {
  count                           = var.create_resources ? 1 : 0
  cluster_identifier              = "${var.identifier_prefix}${var.name}"
  engine                          = var.engine
  engine_version                  = var.engine_version
  kms_key_id                      = var.kms_key_id
  master_username                 = var.username
  master_password                 = local.master_password
  deletion_protection             = var.deletion_protection
  final_snapshot_identifier       = "${var.final_snapshot_identifier_prefix}${var.name}-${random_id.snapshot_identifier[0].hex}"
  skip_final_snapshot             = var.skip_final_snapshot
  backup_retention_period         = var.backup_retention_period
  preferred_backup_window         = var.preferred_backup_window
  preferred_maintenance_window    = var.preferred_maintenance_window
  port                            = local.port
  db_subnet_group_name            = aws_db_subnet_group.main[0].name
  vpc_security_group_ids          = concat([aws_security_group.main[0].id], var.extra_security_groups)
  snapshot_identifier             = var.snapshot_identifier
  storage_encrypted               = var.storage_encrypted
  apply_immediately               = var.apply_immediately
  db_cluster_parameter_group_name = var.db_cluster_parameter_group_name
  tags                            = var.tags

  timeouts {
    create = var.create_timeout
    update = var.update_timeout
    delete = var.delete_timeout
  }
}

resource "aws_rds_cluster_instance" "instance" {
  count                           = local.cluster_instance_count
  identifier                      = "${var.name}-${count.index + 1}"
  cluster_identifier              = aws_rds_cluster.main[0].id
  engine                          = var.engine
  engine_version                  = var.engine_version
  instance_class                  = var.instance_type
  publicly_accessible             = var.publicly_accessible
  db_subnet_group_name            = aws_db_subnet_group.main[0].name
  db_parameter_group_name         = var.db_parameter_group_name
  preferred_backup_window         = var.preferred_backup_window_instance
  preferred_maintenance_window    = var.preferred_maintenance_window_instance
  apply_immediately               = var.apply_immediately
  monitoring_role_arn             = join("", aws_iam_role.rds_enhanced_monitoring.*.arn)
  monitoring_interval             = var.monitoring_interval
  auto_minor_version_upgrade      = var.auto_minor_version_upgrade
  promotion_tier                  = count.index + 1
  #performance_insights_enabled    = var.performance_insights_enabled
  #performance_insights_kms_key_id = var.performance_insights_kms_key_id
  ca_cert_identifier              = var.ca_cert_identifier
  tags                            = var.tags
}

resource "random_id" "snapshot_identifier" {
  count       = var.create_resources ? 1 : 0
  byte_length = 4

  keepers = {
    id = var.name
  }
}

data "aws_iam_policy_document" "monitoring_rds_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds_enhanced_monitoring" {
  count              = local.create_enhanced_monitoring ? 1 : 0
  name               = "rds-enhanced-monitoring-${var.name}"
  assume_role_policy = data.aws_iam_policy_document.monitoring_rds_assume_role.json
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  count      = local.create_enhanced_monitoring ? 1 : 0
  role       = aws_iam_role.rds_enhanced_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_appautoscaling_target" "read_replica_count" {
  count              = var.replica_autoscaling ? 1 : 0
  max_capacity       = var.replica_scale_max
  min_capacity       = var.replica_scale_min
  resource_id        = "cluster:${aws_rds_cluster.main[0].cluster_identifier}"
  scalable_dimension = "rds:cluster:ReadReplicaCount"
  service_namespace  = "rds"
}

resource "aws_appautoscaling_policy" "autoscaling_read_replica_count" {
  count              = var.replica_autoscaling ? 1 : 0
  name               = "target-metric"
  policy_type        = "TargetTrackingScaling"
  resource_id        = "cluster:${aws_rds_cluster.main[0].cluster_identifier}"
  scalable_dimension = "rds:cluster:ReadReplicaCount"
  service_namespace  = "rds"

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "RDSReaderAverageCPUUtilization"
    }

    scale_in_cooldown  = var.replica_scale_in_cooldown
    scale_out_cooldown = var.replica_scale_out_cooldown
    target_value       = var.replica_scale_cpu
  }

  depends_on = [aws_appautoscaling_target.read_replica_count]
}

resource "aws_security_group" "main" {
  count       = var.create_resources ? 1 : 0
  name        = "${var.security_group_name_prefix}${var.name}"
  description = "For Aurora cluster ${var.name}"
  vpc_id      = var.vpc_id
  tags = merge(
    var.tags,
    {
      "Name" = "aurora-${var.name}"
    },
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "default_ingress" {
  count                    = var.create_resources ? length(var.allowed_security_groups) : 0
  type                     = "ingress"
  from_port                = aws_rds_cluster.main[0].port
  to_port                  = aws_rds_cluster.main[0].port
  protocol                 = "tcp"
  source_security_group_id = element(var.allowed_security_groups, count.index)
  security_group_id        = aws_security_group.main[0].id
}

```
___

# Monitoring of RDS Cluster

### Terraform Code file name - cloudwatch.tf

```Terraform

locals {
  cloudwatch_alarm_default_thresholds = {
    "database_connections" = 500
    "cpu_utilization"      = 70
    "disk_queue_depth"     = 20
    "aurora_replica_lag"   = 2000
    "freeable_memory"      = 200000000
    "swap_usage"           = 100000000
  }

  cloudwatch_create_alarms = var.create_resources && var.cloudwatch_create_alarms ? true : false
}

resource "aws_cloudwatch_metric_alarm" "disk_queue_depth" {
  count               = local.cloudwatch_create_alarms ? 1 : 0
  alarm_name          = "rds-${aws_rds_cluster.main[0].id}-writer-DiskQueueDepth"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "DiskQueueDepth"
  namespace           = "AWS/RDS"
  period              = "60"
  statistic           = "Maximum"
  threshold = lookup(
    var.cloudwatch_alarm_default_thresholds,
    "disk_queue_depth",
    local.cloudwatch_alarm_default_thresholds["disk_queue_depth"],
  )
  alarm_description = "RDS Maximum DiskQueueDepth for RDS aurora cluster ${aws_rds_cluster.main[0].id} writer"
  alarm_actions     = var.cloudwatch_alarm_actions
  ok_actions        = var.cloudwatch_alarm_actions

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main[0].id
    Role                = "WRITER"
  }
}

resource "aws_cloudwatch_metric_alarm" "database_connections_writer" {
  count               = local.cloudwatch_create_alarms ? 1 : 0
  alarm_name          = "rds-${aws_rds_cluster.main[0].id}-writer-DatabaseConnections"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "60"
  statistic           = "Sum"
  threshold = lookup(
    var.cloudwatch_alarm_default_thresholds,
    "database_connections",
    local.cloudwatch_alarm_default_thresholds["database_connections"],
  )
  alarm_description = "RDS Maximum connection for RDS aurora cluster ${aws_rds_cluster.main[0].id} writer"
  alarm_actions     = var.cloudwatch_alarm_actions
  ok_actions        = var.cloudwatch_alarm_actions

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main[0].id
    Role                = "WRITER"
  }
}

resource "aws_cloudwatch_metric_alarm" "database_connections_reader" {
  count               = local.cloudwatch_create_alarms && var.replica_count > 0 ? 1 : 0
  alarm_name          = "rds-${aws_rds_cluster.main[0].id}-reader-DatabaseConnections"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "60"
  statistic           = "Maximum"
  threshold = lookup(
    var.cloudwatch_alarm_default_thresholds,
    "database_connections",
    local.cloudwatch_alarm_default_thresholds["database_connections"],
  )
  alarm_description = "RDS Maximum connection for RDS aurora cluster ${aws_rds_cluster.main[0].id} reader(s)"
  alarm_actions     = var.cloudwatch_alarm_actions
  ok_actions        = var.cloudwatch_alarm_actions

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main[0].id
    Role                = "READER"
  }
}

resource "aws_cloudwatch_metric_alarm" "cpu_utilization_writer" {
  count               = local.cloudwatch_create_alarms ? 1 : 0
  alarm_name          = "rds-${aws_rds_cluster.main[0].id}-writer-CPU"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "60"
  statistic           = "Maximum"
  threshold = lookup(
    var.cloudwatch_alarm_default_thresholds,
    "cpu_utilization",
    local.cloudwatch_alarm_default_thresholds["cpu_utilization"],
  )
  alarm_description = "RDS CPU for RDS aurora cluster ${aws_rds_cluster.main[0].id} writer"
  alarm_actions     = var.cloudwatch_alarm_actions
  ok_actions        = var.cloudwatch_alarm_actions

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main[0].id
    Role                = "WRITER"
  }
}

resource "aws_cloudwatch_metric_alarm" "cpu_utilization_reader" {
  count               = local.cloudwatch_create_alarms && var.replica_count > 0 ? 1 : 0
  alarm_name          = "rds-${aws_rds_cluster.main[0].id}-reader-CPU"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "60"
  statistic           = "Maximum"
  threshold = lookup(
    var.cloudwatch_alarm_default_thresholds,
    "cpu_utilization",
    local.cloudwatch_alarm_default_thresholds["cpu_utilization"],
  )
  alarm_description = "RDS CPU for RDS aurora cluster ${aws_rds_cluster.main[0].id} reader(s)"
  alarm_actions     = var.cloudwatch_alarm_actions
  ok_actions        = var.cloudwatch_alarm_actions

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main[0].id
    Role                = "READER"
  }
}

resource "aws_cloudwatch_metric_alarm" "aurora_replica_lag" {
  count               = local.cloudwatch_create_alarms && var.replica_count > 0 ? 1 : 0
  alarm_name          = "rds-${aws_rds_cluster.main[0].id}-reader-AuroraReplicaLag"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "5"
  metric_name         = "AuroraReplicaLag"
  namespace           = "AWS/RDS"
  period              = "60"
  statistic           = "Maximum"
  threshold = lookup(
    var.cloudwatch_alarm_default_thresholds,
    "aurora_replica_lag",
    local.cloudwatch_alarm_default_thresholds["aurora_replica_lag"],
  )
  alarm_description = "RDS CPU for RDS aurora cluster ${aws_rds_cluster.main[0].id}"
  alarm_actions     = var.cloudwatch_alarm_actions
  ok_actions        = var.cloudwatch_alarm_actions

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main[0].id
    Role                = "READER"
  }
}

resource "aws_cloudwatch_metric_alarm" "swap_usage_writer" {
  count               = local.cloudwatch_create_alarms ? 1 : 0
  alarm_name          = "rds-${aws_rds_cluster.main[0].id}-writer-SwapUsage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "SwapUsage"
  namespace           = "AWS/RDS"
  period              = "60"
  statistic           = "Maximum"
  threshold = lookup(
    var.cloudwatch_alarm_default_thresholds,
    "swap_usage",
    local.cloudwatch_alarm_default_thresholds["swap_usage"],
  )
  alarm_description = "RDS swap usage for RDS aurora cluster ${aws_rds_cluster.main[0].id} writer"
  alarm_actions     = var.cloudwatch_alarm_actions
  ok_actions        = var.cloudwatch_alarm_actions

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main[0].id
    Role                = "WRITER"
  }
}

resource "aws_cloudwatch_metric_alarm" "swap_usage_reader" {
  count               = local.cloudwatch_create_alarms && var.replica_count > 0 ? 1 : 0
  alarm_name          = "rds-${aws_rds_cluster.main[0].id}-reader-SwapUsage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "SwapUsage"
  namespace           = "AWS/RDS"
  period              = "60"
  statistic           = "Maximum"
  threshold = lookup(
    var.cloudwatch_alarm_default_thresholds,
    "swap_usage",
    local.cloudwatch_alarm_default_thresholds["swap_usage"],
  )
  alarm_description = "RDS swap usage for RDS aurora cluster ${aws_rds_cluster.main[0].id} reader(s)"
  alarm_actions     = var.cloudwatch_alarm_actions
  ok_actions        = var.cloudwatch_alarm_actions

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main[0].id
    Role                = "READER"
  }
}

resource "aws_cloudwatch_metric_alarm" "freeable_memory_writer" {
  count               = local.cloudwatch_create_alarms ? 1 : 0
  alarm_name          = "rds-${aws_rds_cluster.main[0].id}-writer-FreeableMemory"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = "60"
  statistic           = "Minimum"
  threshold = lookup(
    var.cloudwatch_alarm_default_thresholds,
    "freeable_memory",
    local.cloudwatch_alarm_default_thresholds["freeable_memory"],
  )
  alarm_description = "RDS freeable memory for RDS aurora cluster ${aws_rds_cluster.main[0].id} writer"
  alarm_actions     = var.cloudwatch_alarm_actions
  ok_actions        = var.cloudwatch_alarm_actions

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main[0].id
    Role                = "WRITER"
  }
}

resource "aws_cloudwatch_metric_alarm" "freeable_memory_reader" {
  count               = local.cloudwatch_create_alarms && var.replica_count > 0 ? 1 : 0
  alarm_name          = "rds-${aws_rds_cluster.main[0].id}-reader-FreeableMemory"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = "60"
  statistic           = "Minimum"
  threshold = lookup(
    var.cloudwatch_alarm_default_thresholds,
    "freeable_memory",
    local.cloudwatch_alarm_default_thresholds["freeable_memory"],
  )
  alarm_description = "RDS freeable memory for RDS aurora cluster ${aws_rds_cluster.main[0].id} reader(s)"
  alarm_actions     = var.cloudwatch_alarm_actions
  ok_actions        = var.cloudwatch_alarm_actions

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main[0].id
    Role                = "READER"
  }
}

```

___


## Output codes for RDS Cluster

### Terraform Code file name - output.tf

```Terraform

output "cluster_id" {
  description = "The ID of the cluster"
  value       = concat(aws_rds_cluster.main.*.id, [""])[0]
}

output "cluster_endpoint" {
  description = "The cluster endpoint"
  value       = concat(aws_rds_cluster.main.*.endpoint, [""])[0]
}

output "cluster_reader_endpoint" {
  description = "The cluster reader endpoint"
  value       = concat(aws_rds_cluster.main.*.reader_endpoint, [""])[0]
}

output "cluster_master_username" {
  description = "The master username"
  value       = concat(aws_rds_cluster.main.*.master_username, [""])[0]
}

output "cluster_master_password" {
  description = "The master password"
  value       = concat(aws_rds_cluster.main.*.master_password, [""])[0]
}

output "cluster_port" {
  description = "The port"
  value       = concat(aws_rds_cluster.main.*.port, [""])[0]
}

output "security_group_id" {
  description = "The security group ID of the cluster"
  value       = concat(aws_security_group.main.*.id, [""])[0]
}



