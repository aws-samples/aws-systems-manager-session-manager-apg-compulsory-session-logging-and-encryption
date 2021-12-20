## AWS Systems Manager Sessions Manager Amazon Prescriptive Guidance Compulsory Session Logging and Encryption

## Summary

Customers may choose to delay or disallow the use of AWS Systems Manager Session Manager because they are operating under the impression that it cannot be implemented with strong controls around its use.  This choice to forgo the solution is made despite its ability to accelerate developer workflows and its numerous advantages over traditional access methods such as SSH connections.  

 

This design allows for general implementation of Systems Manager Session Manager logging and encryption while utilizing only a single key for both the session encryption and storage for a given region.  Use of the key and bucket are restricted using a series of constraining conditions in their resource policies to make them resistant to making use of them outside of their intend functions.  

 

The design also makes accommodations for addressing the common naming conflict issues that customers may experience when using creating the default Session document “SSM-SessionManagerRunShell”.  Due to its properties as an AWS account owned resource this SSM document frequently presents issues when IAC solutions attempt to take over managing it.  The document is automatically generated on first run of Session Manager in a given region so developing a mechanism to handle the naming conflict is often necessary.  



An IAM role, Instance Profile, and identity policies are provided by the sample code also, to provide consumers with a simple example they can begin utilizing on their EC2 instances immediately.  This will ensure that they can adopt quickly to the security restrictions that the Session Document implements.

## Prerequisites and limitations

### Prerequisites 
This pattern assumes a relatively modern version of Terraform at least 0.14 or greater.
The customer will need to deploy Terraform pipelines to implement the code samples.
The customer will need to provide their own EC2 Instance and the requisite connectivity so that it can communicate with the KMS, S3, SSM, SSMMessages, and EC2Messages service endpoints.




### Limitations 
This pattern cannot support Systems Manager Sessions for Hybrid Activated Instances.  This solution utilizes a single Customer Managed Key (CMK) located in a logging account.  Hybrid instances cannot use cross account keys for session encryption.

## Architecture
### Target technology stack  

After Implementation the following resources will be created in the designated accounts:

### Security/Logging Account

| AWS Resource | Name                                                  | Description                                                                       |
|--------------|-------------------------------------------------------|-----------------------------------------------------------------------------------|
| KMS Key      | SessionKey                                            | Provides Encryption of Systems Manager Sessions as well as log files stored in S3 |
| S3 Bucket    | [a user defined value]-ssmsessionlogging-[AWS_REGION] | Storage location for all logs generated by System Manager Sessions                |


### Workload(s) Account

| AWS Resource             | Name                                                    | Description                                                                                                                                                                                                                                                                                                                                      |
|--------------------------|---------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| IAM Role                 | /common/examples/EC2-SSMEncryptedLoggedSessions         | A sample IAM Role which will be assigned to an instance profile with the same name.  EC2 instances are assigned an instance profile to give them the permissions of the assigned role. This example role will be able to make use of the key and bucket in the Security/Logging account for session encryption and logging in workload accounts. |
| IAM Role                 | /common/examples/ConsoleSSMSessionTester                | A role with a trust policy allowing the owning account to assume it.  Used for testing Systems Manager Session Manager using a role with the appropriate permissions to launch an EC2 instance  assigned with the test instance profile, and initiate a systems manager session with it.                                                         |
| IAM Managed Policy       | /common/examples/SSMEncryptedLoggedSessions             | A Customer Managed IAM policy which will provide the role with the necessary permissions to encrypt sessions and put logs in the bucket                                                                                                                                                                                                          |
| IAM Managed Policy       | /common/examples/ConsoleSSMSessionTesterRolePermissions | An identity policy assigned to the ConsoleSSMSessionTesterRole.  Has permissions to launch an EC2 instance and pass it the EC2-SSMEncryptedLoggedSessions instance profile.                                                                                                                                                                      |
| Instance Profile         | /common/examples/EC2-SSMEncryptedLoggedSessions         | A sample instance profile which can be provided to EC2 instances granting them the ability to be assigned a role's permissions.                                                                                                                                                                                                                  |
| Systems Manager Document | SSM-SessionManagerRunShell                              | A Systems Manager Session document.  As the default document this session document will be invoked whenever a Systems Manager Session Manager session is started unless the user provides an alternative session document.  It contains the instructions which dictate how the session is encrypted and logged.                                  |

### Target architecture 
[Diagram](Diagram.png)


## License

This library is licensed under the MIT-0 License. See the LICENSE file.