# AWS Service IP Space → SGs → ENIs
A Lambda function to create EC2 Security Groups (SGs) in multiple regions with ingress rules for IP address ranges of an AWS service and attach them to ENIs tagged with `PREFIX_NAME=AUTOUPDATE`.  Typical use-case being to allow access to an EC2 instance or Load Balancer from CloudFront only.  The SGs are replaced whenever the function is invoked, i.e., when triggered by AWS updating IP addresses spaces or when manually invoked (see **Test Event** below).  See **This Solution** below for more details.

## Deployment

This project uses [AWS SAM](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html) to deploy the function along with necessary permissions, SNS trigger from the AmazonIpSpaceChanged topic, and SNS dead-letter-queue with a subscription to an email address for receiving notifications on lambda failures.

This lambda function subscribes to the [AmazonIpSpaceChanged](http://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html#subscribe-notifications) SNS topic.  As this topic is in us-east-1 region the subscription (and therefore this function) **must be deployed to the us-east-1 region** also.

**Top Tip:** Create a `samconfig.toml` file in the project root to specify use-case specific settings and overrides (example below).  This is required at least to provide parameter overrides to the stack for `NotificationEmail`, `IngressPorts`, and `RegionList`.  See **Configuration** section for full list of parameters that can be overridden.  After making changes run `sam deploy` to action the changes.

```toml
version = 0.1
[default]
[default.deploy]
[default.deploy.parameters]
stack_name = "AWS-IPs-to-SGs-to-ENIs"
s3_bucket = "*** YOUR-SAM-DEPLOYMENT-BUCKET-HERE ***"
s3_prefix = "AWS-IPs-to-SGs-to-ENIs"
region = "us-east-1"
confirm_changeset = false
capabilities = "CAPABILITY_IAM"
parameter_overrides = "IngressPorts=\"*** YOUR PORT LIST HERE ***\" RegionList=\"eu-west-1\" NotificationEmail=\"*** YOUR EMAIL ADDRESS HERE ***\""
```

## Configuration

| CloudFormation  Parameter | Environment Variable | Purpose                                                      | Default      |
| - | ----------------- | ------------------------------------------------------------ | ------------ |
| RegionList | `REGIONS`         | Comma separated list of regions to process.  Consider increasing lambda timeout if including many regions in this list. | `eu-west-1`  |
| PrefixName | `PREFIX_NAME`     | The "value" to assign this tag on the created SGs.  ENIs tagged the same will have the SGs attached. | `AUTOUPDATE` |
| Service | `SERVICE`         | Service name as referred to in responses from https://ip-ranges.amazonaws.com/ip-ranges.json (e.g. API_GATEWAY, CLOUDFRONT, etc) | `CLOUDFRONT` |
| IngressPorts | `PORTS`           | Comma separated list of TCP ports or port-ranges to allow (e.g. 80,443,8080-8081) | `8080-8081` |
| n/a | `DEBUG`       | Enables extra lambda function logging to CloudWatch Logs | `true` |
| SNSTopicARN | n/a | Provide ARN of the AmazonIpSpaceChanged topic. | `arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged` |
| NotificationEmail | n/a | Address to send function failure notification emails | n/a |

## Resilience

The project uses the Boto3 SDK to make API calls to AWS services.  Boto's inbuilt retry mechanism should help make this function resilient to transient failures.  Any Boto client call that fails will raise an exception causing the function to exit with failure status.  AWS Lambda automatically retries aynchronously invoked lambdas such as this when they fail, which should also help address transient errors.  Errors that continue to fail will trigger a notification to the subscribed email address via the SNS dead-letter-queue mechanism.  Any email received as such should be considered important as it could mean that the protected ENIs are now relying on possibly out-of-date IP address ranges.  Manual retries of this function should be attempted until it succeeds or the problem is identified and resolved.

A dropped SNS message from the AmazonIpSpaceChanged topic would not be caught obviously, but this is presumed to have a very low probability of occurring.

## Test Event

In the events directory of this repo is an `events.json` file containing an example notification from the AmazonIpSpaceChanged topic.  This can be use to test the function manually in the AWS Lambda console or in a development environment (e.g. sam local).  It can also be used whenever there is a need to re-run the function outside of being invoked by notifications from the AmazonIpSpaceChanged topic, such as when the list of regions or ports needs to be changed, or when there are newly tagged ENIs to associate SGs to.

When the test is executed it will typically report an `MD5 Mismatch` error (in the logs) -- this is expected as whenever AWS IP address spaces change this hash will also change.  Simply update the event configuration in the AWS Lambda console with the new hash reported in the error log and retry the test.

# Background

AWS service endpoints (such as CloudFront) change periodically, swapping and changing, but typically increasing in number as the AWS points-of-presence increase over time.  Consequently requests to origins from these services will have ever changing source IP addresses, and locking-down access to origins from just these addresses is not as trivial as it might sound.

Different types of origin can make use of different protection mechanisms:

- S3 origins can limit access via the Origin Access Identity mechanism, which restricts bucket access to just CloudFront.  This is easy.
- Load Balancer origins can use a Web-Application-Firewall (WAF) with an IP Set of CloudFront address ranges (see: [aws-samples/aws-cloudfront-waf-ip-set](https://github.com/aws-samples/aws-cloudfront-waf-ip-set)).
- Load Balancers can alternatively use **SGs** to limit access.
- EC2 origins can only use **SGs** to limit access.

This solution focuses on the SGs approach.

## Security Group Limitations

A SG ingress rule is needed for each port or port-range for each address range that needs to be allowed.  As of writing, the CloudFront service has 120 IPv4 address ranges (see below for note on IPv6).  Therefore, if ports 80, 443, and 8080-8081 are to be allowed then a total of 360 rules would be needed (i.e. 120 x 3 rules).  If a project suddenly needs an additional port then that's another 120 ingress rules to add.  Persistent and unchanging rules, providing access to monitoring ports and SSH, etc, also need to be considered separately, but at the same time within the final total.

At the time of writing, the number of SG ingress rules is limited to 60 by default, and EC2 instances and Load Balancers (i.e., their ENIs) can have up to 5 SGs attached, totalling 300 ingress rules.  Both limits can be adjusted by issuing **region-specific** quota increase support requests to AWS, however the total number of rules per ENI cannot exceed 1000.

## Existing Solutions

Existing solutions ([made by AWS](https://github.com/aws-samples/aws-cloudfront-samples/tree/master/update_security_groups_lambda) and [enhanced here](https://github.com/ahibbitt/cloudfront_sg_manager)) attempt to maintain a fixed set of SGs, for a fixed (limited) set of ports / protocols, recycing the same groups to remove expired addresses and add new addresses wherever they will fit.  This is a complicated approach and will never automatically take advantage of any increase in region specific SG limits.  Consequently, these solutions will fail as soon as service IP address ranges expand or user port requirements increase beyond the limits afforded by the fixed set of SGs.

A [more recent approach](https://aws.amazon.com/blogs/security/automatically-update-security-groups-for-amazon-cloudfront-ip-ranges-using-aws-lambda/) (that this solution borrows ideas from) attempts to create additional SGs as needed, but does not take into consideration per-region quota limits.  It is also a complicated (clever?) piece of code in that it still attempts to surgically splice revocations and new additions into existing SGs only adding new ones when needed.  When the requirements contract you're left with superfluous SGs with zero rules.  It also didn't work well when port/port-ranges were changed, and it wiped-out any pre-existing SGs attached to ENIs (for SSH, etc).

In summary, while these approaches worked well within fixed scenarios, they have a short shelf-life and need to be tweaked whenever user changes are needed or the inevitable happens (an outage).

## This Solution

This solution borrows ideas from the above methods to an extent but simplifies by borrowing ideas from throw-away immutable container deployment practices: i.e. it does not attempt to mutate a fixed set of SGs in-place, instead it creates new SGs according to the latest information available *at invocation time*, (i.e. How many *Service* IP ranges, *right-now*?  How many ports, *right-now*?  What are the region-specific limits, *right-now*?).   Like containers, old SGs are destroyed as soon as the new SGs take their place on ENIs.  Any separate SGs for perpetual rules (for SSH, VPNs, etc) already attached to ENIs survive these SG replacements -- in one atomic operation.

The high level steps are:

1. Retrieves latest IP ranges from AWS' endpoint
2. Creates one big list of ingress rules (for all IP ranges and ports/port-ranges)
3. Determine SG limits for the region (rules per SG, and SGs per ENI)
4. Test if anything has actually changed otherwise end here**
5. Creates sufficient SGs to hold all the rules (maybe different in each region)
6. Split ingress rules across created SGs
7. Switch old for new SGs on each tagged ENI
8. Destroy old SGs

** Note that IP ranges returned from https://ip-ranges.amazonaws.com/ip-ranges.json reach into the thousands as they cover many AWS services.  On aggregate they change frequently (well, about once or twice a day on most weeks).  The subset of IP addresses for a particular service may change much less frequently though.  For instance, the CloudFront subset of IP addresses represents just 3% of the total IP ranges advertised, so they may change very rarely indeed.  This solution only replaces SGs (steps 5 to 8) when that subset itself changes, or when the number of SGs required changes (i.e., due to updated limits), or the ports/port-range rules change, or the tagged ENIs have changed (to automatically include newly tagged ENIs).

## Limitations

Only supports regions' default VPC, but extending to named VPCs could be easily implemented.

## CloudFront and IPv6

While there are both IPv4 addresses and IPv6 addresses included in the response for CloudFront, this function only extracts and uses the IPv4 addresses because [CloudFront communicates to origins using IPv4 only](https://cloudonaut.io/getting-started-with-ipv6-on-aws/).  If this ever changes (and assuming the origin is also dual-stack) then modifying the function to support IPv6 should be trivial.  Incidentally, CloudFront *client-side* support of IPv6 is irrelevant to this concern.
