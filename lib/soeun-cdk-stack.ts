import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as lambdaEventSources from 'aws-cdk-lib/aws-lambda-event-sources';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as glue from 'aws-cdk-lib/aws-glue';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as scheduler from 'aws-cdk-lib/aws-scheduler';
import * as athena from 'aws-cdk-lib/aws-athena';
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
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonCognitoPowerUser'),
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
        indexName: 'conversationId-createdAt-index',
        partitionKey: { name: 'conversationId', type: dynamodb.AttributeType.STRING },
        sortKey: { name: 'createdAt', type: dynamodb.AttributeType.STRING },
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

    // SPA 클라이언트 (secret 없음, 프론트엔드용 - 현재 미사용)
    userPool.addClient('SeReportAppSpa', {
      userPoolClientName: 'se-report-app',
      generateSecret: false,
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.GOOGLE],
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.EMAIL, cognito.OAuthScope.OPENID, cognito.OAuthScope.PROFILE],
        callbackUrls: [
          'http://localhost:3000/auth/callback',
          'https://soeun-report-frontend.vercel.app/auth/callback',
        ],
        logoutUrls: [
          'http://localhost:3000',
          'https://soeun-report-frontend.vercel.app',
        ],
      },
    });

    // 서버 클라이언트 (secret 있음, Spring Boot 백엔드용)
    const serverClient = userPool.addClient('SeReportAppServer', {
      userPoolClientName: 'se-report-server',
      generateSecret: true,
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.GOOGLE],
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.EMAIL, cognito.OAuthScope.OPENID, cognito.OAuthScope.PROFILE],
        callbackUrls: [
          'http://localhost:3000/auth/callback',
          'https://soeun-report-frontend.vercel.app/auth/callback',
        ],
        logoutUrls: [
          'http://localhost:3000',
          'https://soeun-report-frontend.vercel.app',
        ],
      },
    });

    // ───────────────────────────────
    // 9. 인증 Lambda (auth/index.mjs)
    // ───────────────────────────────
    const authLambda = new lambda.Function(this, 'SeAuthLambda', {
      functionName: 'se-auth-lambda',
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/auth')),
      environment: {
        COGNITO_DOMAIN: 'https://ap-northeast-2bzej4aji8.auth.ap-northeast-2.amazoncognito.com',
        CLIENT_ID: serverClient.userPoolClientId,
        CLIENT_SECRET: serverClient.userPoolClientSecret.unsafeUnwrap(),
        // [수정] 로컬/프로덕션 분리
        REDIRECT_URI_LOCAL: 'http://localhost:3000/auth/callback',
        REDIRECT_URI_PROD: 'https://soeun-report-frontend.vercel.app/auth/callback',
      },
      timeout: cdk.Duration.seconds(10),
    });

    // ───────────────────────────────
    // 10. SQS (배치 파이프라인)
    // ───────────────────────────────
    const batchDlq = new sqs.Queue(this, 'SeBatchDlq', {
      queueName: 'se-batch-dlq',
      retentionPeriod: cdk.Duration.days(14),
    });

    const batchQueue = new sqs.Queue(this, 'SeBatchQueue', {
      queueName: 'se-batch-queue',
      visibilityTimeout: cdk.Duration.seconds(300),
      retentionPeriod: cdk.Duration.days(4),
      deadLetterQueue: {
        queue: batchDlq,
        maxReceiveCount: 3,
      },
    });

    // ───────────────────────────────
    // 11. IAM Role - 배치 Lambda용
    // ───────────────────────────────
    const batchLambdaRole = new iam.Role(this, 'SeBatchLambdaRole', {
      roleName: 'se-batch-lambda-role',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaSQSQueueExecutionRole'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonS3FullAccess'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AWSGlueServiceRole'),
      ],
    });

    // ───────────────────────────────
    // 12. 배치 Lambda (batch/function.py)
    // ───────────────────────────────
    const batchLambda = new lambda.Function(this, 'SeBatchLambda', {
      functionName: 'se-batch-lambda',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'function.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/batch')),
      role: batchLambdaRole,
      timeout: cdk.Duration.minutes(5),
      layers: [
        lambda.LayerVersion.fromLayerVersionArn(
          this, 'AWSSDKPandasLayer',
          'arn:aws:lambda:ap-northeast-2:336392948345:layer:AWSSDKPandas-Python312:16'
        ),
      ],
      environment: {
        GOOGLE_DEVELOPER_TOKEN: process.env.GOOGLE_DEVELOPER_TOKEN || '',
        GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || '',
        GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || '',
        GOOGLE_REFRESH_TOKEN: process.env.GOOGLE_REFRESH_TOKEN || '',
        GOOGLE_CUSTOMER_ID: process.env.GOOGLE_CUSTOMER_ID || '',
        KAKAO_REST_API_KEY: process.env.KAKAO_REST_API_KEY || '',
        KAKAO_CLIENT_SECRET: process.env.KAKAO_CLIENT_SECRET || '',
        KAKAO_REFRESH_TOKEN: process.env.KAKAO_REFRESH_TOKEN || '',
        S3_BUCKET_NAME: adDataBucket.bucketName,
      },
    });

    // 배치 Lambda SQS 트리거
    batchLambda.addEventSource(new lambdaEventSources.SqsEventSource(batchQueue, {
      batchSize: 1,
    }));

    // ───────────────────────────────
    // 13. DLQ Lambda (dlq/function.py)
    // ───────────────────────────────
    const dlqLambdaRole = new iam.Role(this, 'SeDlqLambdaRole', {
      roleName: 'se-dlq-lambda-role',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaSQSQueueExecutionRole'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchFullAccess'),
      ],
    });

    const dlqLambda = new lambda.Function(this, 'SeDlqLambda', {
      functionName: 'se-dlq-lambda',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'function.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/dlq')),
      role: dlqLambdaRole,
      timeout: cdk.Duration.seconds(30),
    });

    // DLQ Lambda 트리거
    dlqLambda.addEventSource(new lambdaEventSources.SqsEventSource(batchDlq, {
      batchSize: 1,
    }));

    // ───────────────────────────────
    // 14. IAM Role - EventBridge Scheduler용
    // ───────────────────────────────
    const scheduleGroup = new scheduler.CfnScheduleGroup(this, 'SeScheduleGroup', {
      name: 'soeun',
    });

    const schedulerRole = new iam.Role(this, 'SeSchedulerRole', {
      roleName: 'se-batch-eventbridge-role',
      assumedBy: new iam.ServicePrincipal('scheduler.amazonaws.com'),
      inlinePolicies: {
        SendMessagePolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: ['sqs:SendMessage'],
              resources: [batchQueue.queueArn, batchDlq.queueArn],
            }),
          ],
        }),
      },
    });

    // ───────────────────────────────
    // 15. EventBridge Scheduler - 배치
    // 매일 새벽 3시 KST = UTC 18:00
    // ───────────────────────────────
    const batchScheduleExpression = 'cron(0 18 * * ? *)';

    new scheduler.CfnSchedule(this, 'SeBatchScheduleGoogle', {
      name: 'se-batch-schedule-google',
      groupName: scheduleGroup.name,
      scheduleExpression: batchScheduleExpression,
      flexibleTimeWindow: { mode: 'OFF' },
      target: {
        arn: batchQueue.queueArn,
        roleArn: schedulerRole.roleArn,
        input: JSON.stringify({ platform: 'google' }),
        retryPolicy: {
          maximumRetryAttempts: 3,
          maximumEventAgeInSeconds: 86400,
        },
        deadLetterConfig: { arn: batchDlq.queueArn },
      },
    });

    new scheduler.CfnSchedule(this, 'SeBatchScheduleKakao', {
      name: 'se-batch-schedule-kakao',
      groupName: scheduleGroup.name,
      scheduleExpression: batchScheduleExpression,
      flexibleTimeWindow: { mode: 'OFF' },
      target: {
        arn: batchQueue.queueArn,
        roleArn: schedulerRole.roleArn,
        input: JSON.stringify({ platform: 'kakao' }),
        retryPolicy: {
          maximumRetryAttempts: 3,
          maximumEventAgeInSeconds: 86400,
        },
        deadLetterConfig: { arn: batchDlq.queueArn },
      },
    });

    // ───────────────────────────────
    // 16. 리포트 Lambda (report/function.py)
    // 매주 월요일 08:00 KST = UTC 일요일 23:00
    // ───────────────────────────────
    const reportLambdaRole = new iam.Role(this, 'SeReportLambdaRole', {
      roleName: 'se-report-lambda-role',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonBedrockFullAccess'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonAthenaFullAccess'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonS3FullAccess'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonDynamoDBFullAccess'),
      ],
    });

    const reportLambda = new lambda.Function(this, 'SeReportLambda', {
      functionName: 'se-report-lambda',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'function.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/report')),
      role: reportLambdaRole,
      timeout: cdk.Duration.minutes(5),
      layers: [
        lambda.LayerVersion.fromLayerVersionArn(
          this, 'AWSSDKPandasLayerReport',
          'arn:aws:lambda:ap-northeast-2:336392948345:layer:AWSSDKPandas-Python312:16'
        ),
      ],
      environment: {
        BEDROCK_MODEL_ID: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        DYNAMODB_REPORTS_TABLE: 'se_reports',
        ATHENA_DATABASE: 'se_report_db',
        ATHENA_WORKGROUP: 'se-report-workgroup',
        S3_BUCKET_NAME: adDataBucket.bucketName,
      },
    });

    // 리포트 Lambda EventBridge Scheduler Role
    const reportSchedulerRole = new iam.Role(this, 'SeReportSchedulerRole', {
      roleName: 'se-report-eventbridge-role',
      assumedBy: new iam.ServicePrincipal('scheduler.amazonaws.com'),
      inlinePolicies: {
        InvokeLambdaPolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: ['lambda:InvokeFunction'],
              resources: [reportLambda.functionArn],
            }),
          ],
        }),
      },
    });

    // 매주 월요일 08:00 KST (UTC 일요일 23:00)
    new scheduler.CfnSchedule(this, 'SeWeeklyReportSchedule', {
      name: 'se-weekly-report-schedule',
      groupName: scheduleGroup.name,
      scheduleExpression: 'cron(0 23 ? * SUN *)',
      flexibleTimeWindow: { mode: 'OFF' },
      target: {
        arn: reportLambda.functionArn,
        roleArn: reportSchedulerRole.roleArn,
        input: JSON.stringify({ type: 'weekly_report' }),
        retryPolicy: {
          maximumRetryAttempts: 2,
          maximumEventAgeInSeconds: 3600,
        },
      },
    });

    // ───────────────────────────────
    // 17. Athena 워크그룹
    // ───────────────────────────────
    new athena.CfnWorkGroup(this, 'SeReportAthenaWorkgroup', {
      name: 'se-report-workgroup',
      workGroupConfiguration: {
        resultConfiguration: {
          outputLocation: `s3://${adDataBucket.bucketName}/athena-results/`,
        },
        enforceWorkGroupConfiguration: true,
        publishCloudWatchMetricsEnabled: true,
      },
    });

    // ───────────────────────────────
    // 18. Glue
    // ───────────────────────────────
    const glueDb = new glue.CfnDatabase(this, 'SeReportGlueDb', {
      catalogId: this.account,
      databaseInput: { name: 'se_report_db' },
    });

    const googleColumns = [
      { name: 'camp_id', type: 'string' },
      { name: 'camp_name', type: 'string' },
      { name: 'camp_advertising_channel_type', type: 'string' },
      { name: 'camp_status', type: 'string' },
      { name: 'agroup_id', type: 'string' },
      { name: 'agroup_name', type: 'string' },
      { name: 'agroup_type', type: 'string' },
      { name: 'creation_id', type: 'string' },
      { name: 'creation_name', type: 'string' },
      { name: 'creation_type', type: 'string' },
      { name: 'creation_status', type: 'string' },
      { name: 'creation_final_urls', type: 'string' },
      { name: 'keyword_id', type: 'string' },
      { name: 'keyword_text', type: 'string' },
      { name: 'keyword_match_type', type: 'string' },
      { name: 'device', type: 'string' },
      { name: 'network_type', type: 'string' },
      { name: 'basic_date', type: 'string' },
      { name: 'adv_id', type: 'string' },
      { name: 'date', type: 'string' },
      { name: 'quarter', type: 'string' },
      { name: 'day_of_week', type: 'string' },
      { name: 'week', type: 'string' },
      { name: 'impressions', type: 'bigint' },
      { name: 'clicks', type: 'bigint' },
      { name: 'video_views', type: 'bigint' },
      { name: 'all_conversions', type: 'bigint' },
      { name: 'conversions', type: 'bigint' },
      { name: 'cost_micros', type: 'double' },
      { name: 'ctr', type: 'double' },
      { name: 'average_cpc', type: 'double' },
      { name: 'all_conversions_value', type: 'double' },
      { name: 'conversions_value', type: 'double' },
      { name: 'value_per_conversion', type: 'double' },
      { name: 'cost_per_conversion', type: 'double' },
      { name: 'conversions_from_interactions_rate', type: 'double' },
      { name: 'video_quartile_p25_rate', type: 'double' },
      { name: 'video_quartile_p50_rate', type: 'double' },
      { name: 'video_quartile_p75_rate', type: 'double' },
      { name: 'video_quartile_p100_rate', type: 'double' },
    ];

    const kakaoColumns = [
      { name: 'kwd_id', type: 'string' },
      { name: 'kwd_name', type: 'string' },
      { name: 'kwd_config', type: 'string' },
      { name: 'kwd_url', type: 'string' },
      { name: 'kwd_bid_type', type: 'string' },
      { name: 'agroup_id', type: 'string' },
      { name: 'agroup_name', type: 'string' },
      { name: 'camp_id', type: 'string' },
      { name: 'camp_name', type: 'string' },
      { name: 'camp_type', type: 'string' },
      { name: 'biz_id', type: 'string' },
      { name: 'biz_name', type: 'string' },
      { name: 'lu_pc', type: 'string' },
      { name: 'lu_mobile', type: 'string' },
      { name: 'basic_date', type: 'string' },
      { name: 'adv_id', type: 'string' },
      { name: 'kwd_bid_amount', type: 'bigint' },
      { name: 'imp', type: 'bigint' },
      { name: 'click', type: 'bigint' },
      { name: 'rimp', type: 'bigint' },
      { name: 'rank', type: 'bigint' },
      { name: 'conv_cmpt_reg_1d', type: 'bigint' },
      { name: 'conv_cmpt_reg_7d', type: 'bigint' },
      { name: 'conv_view_cart_1d', type: 'bigint' },
      { name: 'conv_view_cart_7d', type: 'bigint' },
      { name: 'conv_purchase_1d', type: 'bigint' },
      { name: 'conv_purchase_7d', type: 'bigint' },
      { name: 'conv_participation_1d', type: 'bigint' },
      { name: 'conv_participation_7d', type: 'bigint' },
      { name: 'conv_signup_1d', type: 'bigint' },
      { name: 'conv_signup_7d', type: 'bigint' },
      { name: 'conv_app_install_1d', type: 'bigint' },
      { name: 'conv_app_install_7d', type: 'bigint' },
      { name: 'spending', type: 'double' },
      { name: 'ctr', type: 'double' },
      { name: 'ppc', type: 'double' },
      { name: 'conv_purchase_p_1d', type: 'double' },
      { name: 'conv_purchase_p_7d', type: 'double' },
    ];

    const partitionKeys = [
      { name: 'year', type: 'string' },
      { name: 'month_p', type: 'string' },
      { name: 'day', type: 'string' },
    ];

    const serdeInfo = {
      serializationLibrary: 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe',
      parameters: { 'parquet.compression': 'SNAPPY' },
    };

    const googleTable = new glue.CfnTable(this, 'GoogleAdPerformanceTable', {
      catalogId: this.account,
      databaseName: 'se_report_db',
      tableInput: {
        name: 'google_ad_performance',
        storageDescriptor: {
          location: `s3://${adDataBucket.bucketName}/raw/google/`,
          inputFormat: 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
          outputFormat: 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
          serdeInfo,
          columns: googleColumns,
        },
        partitionKeys,
        tableType: 'EXTERNAL_TABLE',
        parameters: { 'EXTERNAL': 'TRUE' },
      },
    });
    googleTable.node.addDependency(glueDb);

    const kakaoTable = new glue.CfnTable(this, 'KakaoAdPerformanceTable', {
      catalogId: this.account,
      databaseName: 'se_report_db',
      tableInput: {
        name: 'kakao_ad_performance',
        storageDescriptor: {
          location: `s3://${adDataBucket.bucketName}/raw/kakao/`,
          inputFormat: 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
          outputFormat: 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
          serdeInfo,
          columns: kakaoColumns,
        },
        partitionKeys,
        tableType: 'EXTERNAL_TABLE',
        parameters: { 'EXTERNAL': 'TRUE' },
      },
    });
    kakaoTable.node.addDependency(glueDb);

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
    new cdk.CfnOutput(this, 'BatchQueueUrl', {
      value: batchQueue.queueUrl,
      description: 'Batch SQS Queue URL',
    });
    new cdk.CfnOutput(this, 'ReportLambdaArn', {
      value: reportLambda.functionArn,
      description: 'Weekly Report Lambda ARN',
    });
    new cdk.CfnOutput(this, 'AthenaWorkgroup', {
      value: 'se-report-workgroup',
      description: 'Athena Workgroup Name',
    });
  }
}