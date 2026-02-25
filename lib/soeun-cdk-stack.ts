import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import { Construct } from 'constructs';

export class SoeunCdkStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ───────────────────────────────
    // 1. VPC
    // ───────────────────────────────
    const vpc = new ec2.Vpc(this, 'SeReportVpc', {
      vpcName: 'se-report-vpc',
      maxAzs: 2,
      ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
      subnetConfiguration: [
        {
          name: 'public',
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 20,
        },
        {
          name: 'private',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 20,
        },
      ],
      natGateways: 0,
    });

    // ───────────────────────────────
    // 2. 보안그룹 - EC2용
    // ───────────────────────────────
    const ec2Sg = new ec2.SecurityGroup(this, 'SeReportEc2Sg', {
      securityGroupName: 'se-report-ec2-sg',
      vpc,
      description: 'Security group for EC2',
      allowAllOutbound: true,
    });

    // SSH - 내 IP만 (실제 IP로 변경 필요)
    ec2Sg.addIngressRule(
      ec2.Peer.anyIpv4(), // 아래와 같이 본인 IP로 변경하기
      // ec2.Peer.ipv4('x.x.x.x/32'),
      ec2.Port.tcp(22),
      'Allow SSH'
    );

    // Spring Boot 포트
    ec2Sg.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(8080),
      'Allow Spring Boot'
    );

    // ───────────────────────────────
    // 3. IAM Role - EC2용
    // ───────────────────────────────
    const ec2Role = new iam.Role(this, 'SeReportEc2Role', {
      roleName: 'se-report-ec2-role',
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'EC2 role for AI report system',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonBedrockFullAccess'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonAthenaFullAccess'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonS3FullAccess'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonDynamoDBFullAccess'),
      ],
    });

    // ───────────────────────────────
    // 4. EC2
    // ───────────────────────────────
    const instance = new ec2.Instance(this, 'SeReportEc2', {
      instanceName: 'se-report-ec2',
      instanceType: ec2.InstanceType.of(
        ec2.InstanceClass.T3,
        ec2.InstanceSize.SMALL
      ),
      // Ubuntu 24.04 LTS
      machineImage: ec2.MachineImage.fromSsmParameter(
        '/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id'
      ),
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      securityGroup: ec2Sg,
      role: ec2Role,
      keyPair: ec2.KeyPair.fromKeyPairName(this, 'KeyPair', 'se-report-key'),
    });

        // ───────────────────────────────
    // 5. ECR
    // ───────────────────────────────
    const repo = new ecr.Repository(this, 'SeReportEcr', {
      repositoryName: 'se-report-server',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      emptyOnDelete: true,
    });

    // ───────────────────────────────
    // 6. S3
    // ───────────────────────────────
 

    // ───────────────────────────────
    // Output
    // ───────────────────────────────
    new cdk.CfnOutput(this, 'EC2PublicIp', {
      value: instance.instancePublicIp,
      description: 'EC2 Public IP',
    });

    new cdk.CfnOutput(this, 'EcrRepositoryUri', {
      value: repo.repositoryUri,
      description: 'ECR Repository URI',
    });

  }
}