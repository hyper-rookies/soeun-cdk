import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as glue from 'aws-cdk-lib/aws-glue';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as path from 'path';
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
        { name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 20 },
        { name: 'private', subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 20 },
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
    ec2Sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'Allow SSH');
    ec2Sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(8080), 'Allow Spring Boot');

    // ───────────────────────────────
    // 3. IAM Role - EC2용
    // ───────────────────────────────
    const ec2Role = new iam.Role(this, 'SeReportEc2Role', {
      roleName: 'se-report-ec2-role',
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
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
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
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
    const adDataBucket = new s3.Bucket(this, 'SeReportAdData', {
      bucketName: 'se-report-ad-data',
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // ───────────────────────────────
    // 7. DynamoDB
    // ───────────────────────────────
    new dynamodb.TableV2(this, 'SeAdAccounts', {
      tableName: 'se_ad_accounts',
      partitionKey: { name: 'userId', type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    new dynamodb.TableV2(this, 'SeConversations', {
      tableName: 'se_conversations',
      partitionKey: { name: 'conversationId', type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      globalSecondaryIndexes: [{
        indexName: 'userId-index',
        partitionKey: { name: 'userId', type: dynamodb.AttributeType.STRING },
      }],
    });

    new dynamodb.TableV2(this, 'SeMessages', {
      tableName: 'se_messages',
      partitionKey: { name: 'messageId', type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      globalSecondaryIndexes: [{
        indexName: 'conversationId-index',
        partitionKey: { name: 'conversationId', type: dynamodb.AttributeType.STRING },
      }],
    });

    new dynamodb.TableV2(this, 'SeReports', {
      tableName: 'se_reports',
      partitionKey: { name: 'reportId', type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      globalSecondaryIndexes: [{
        indexName: 'userId-index',
        partitionKey: { name: 'userId', type: dynamodb.AttributeType.STRING },
        sortKey: { name: 'expiresAt', type: dynamodb.AttributeType.STRING },
      }],
    });

    // ───────────────────────────────
    // 8. Cognito
    // ───────────────────────────────
    const userPool = new cognito.UserPool(this, 'SeReportUserPool', {
      userPoolName: 'se-report-userpool',
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      autoVerify: { email: true },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    userPool.addDomain('SeReportDomain', {
      cognitoDomain: { domainPrefix: 'se-report' },
    });

    new cognito.UserPoolIdentityProviderGoogle(this, 'SeReportGoogle', {
      userPool,
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecretValue: cdk.SecretValue.unsafePlainText(process.env.GOOGLE_CLIENT_SECRET || ''),
      scopes: ['email', 'openid', 'profile'],
      attributeMapping: {
        email: cognito.ProviderAttribute.GOOGLE_EMAIL,
        fullname: cognito.ProviderAttribute.GOOGLE_NAME,
      },
    });

    userPool.addClient('SeReportAppSpa', {
      userPoolClientName: 'se-report-app',
      generateSecret: false,
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.GOOGLE],
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.EMAIL, cognito.OAuthScope.OPENID, cognito.OAuthScope.PROFILE],
        callbackUrls: ['http://localhost:3000/callback'],
        logoutUrls: ['http://localhost:3000'],
      },
    });

    const serverClient = userPool.addClient('SeReportAppServer', {
      userPoolClientName: 'se-report-server',
      generateSecret: true,
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.GOOGLE],
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.EMAIL, cognito.OAuthScope.OPENID, cognito.OAuthScope.PROFILE],
        callbackUrls: ['http://localhost:3000/callback'],
        logoutUrls: ['http://localhost:3000'],
      },
    });

    // ───────────────────────────────
    // 9. 인증 Lambda
    // ───────────────────────────────
    const authLambda = new lambda.Function(this, 'SeAuthLambda', {
      functionName: 'se-auth-lambda',
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/auth')),
      environment: {
        COGNITO_DOMAIN: 'https://se-report.auth.ap-northeast-2.amazoncognito.com',
        CLIENT_ID: serverClient.userPoolClientId,
        REDIRECT_URI: 'http://localhost:3000/callback',
      },
      timeout: cdk.Duration.seconds(10),
    });

    // ───────────────────────────────
    // 10. API Gateway
    // ───────────────────────────────
    const api = new apigateway.RestApi(this, 'SeReportApi', {
      restApiName: 'se-report-api',
      endpointTypes: [apigateway.EndpointType.REGIONAL],
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
      },
    });

    const cognitoAuthorizer = new apigateway.CognitoUserPoolsAuthorizer(this, 'SeReportAuthorizer', {
      authorizerName: 'se-cognito-authorizer',
      cognitoUserPools: [userPool],
    });

    const authResource = api.root.addResource('auth');
    const lambdaIntegration = new apigateway.LambdaIntegration(authLambda);
    authResource.addResource('token').addMethod('POST', lambdaIntegration);
    authResource.addResource('refresh').addMethod('POST', lambdaIntegration);
    authResource.addResource('logout').addMethod('POST', lambdaIntegration);

    // ───────────────────────────────
    // 11. Glue
    // ───────────────────────────────
    const glueDb = new glue.CfnDatabase(this, 'SeReportGlueDb', {
      catalogId: this.account,
      databaseInput: { name: 'se_report_db' },
    });

    const glueTable = new glue.CfnTable(this, 'SeAdPerformanceTable', {
      catalogId: this.account,
      databaseName: 'se_report_db',
      tableInput: {
        name: 'se_ad_performance_parquet',
        storageDescriptor: {
          location: `s3://${adDataBucket.bucketName}/raw/`,
          inputFormat: 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
          outputFormat: 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
          serdeInfo: {
            serializationLibrary: 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe',
            parameters: { 'parquet.compression': 'SNAPPY' },
          },
          columns: [
            { name: 'date', type: 'string' },
            { name: 'campaign_id', type: 'string' },
            { name: 'campaign_name', type: 'string' },
            { name: 'ad_group_id', type: 'string' },
            { name: 'ad_group_name', type: 'string' },
            { name: 'impressions', type: 'bigint' },
            { name: 'clicks', type: 'bigint' },
            { name: 'cost', type: 'double' },
            { name: 'conversions', type: 'bigint' },
            { name: 'conversion_value', type: 'double' },
          ],
        },
        partitionKeys: [
          { name: 'platform', type: 'string' },
          { name: 'year', type: 'string' },
          { name: 'month', type: 'string' },
          { name: 'day', type: 'string' },
        ],
        tableType: 'EXTERNAL_TABLE',
        parameters: { 'EXTERNAL': 'TRUE' },
      },
    });
    glueTable.node.addDependency(glueDb);

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
    new cdk.CfnOutput(this, 'UserPoolId', {
      value: userPool.userPoolId,
      description: 'Cognito User Pool ID',
    });
    new cdk.CfnOutput(this, 'ApiGatewayUrl', {
      value: api.url,
      description: 'API Gateway URL',
    });
  }
}