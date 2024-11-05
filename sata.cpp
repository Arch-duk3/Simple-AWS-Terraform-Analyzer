#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <map>
#include <memory>
#include <sstream>
#include <set>
using namespace std;

// Interface for configuration items
class IConfigurable {
public:
    virtual ~IConfigurable() = default;
    virtual bool validate() const = 0;
    virtual string getType() const = 0;
    virtual string getName() const = 0;
};

// Base class for configuration items
class ConfigurationItem : public IConfigurable {
protected:
    string type;
    string name;
    map<string, string> attributes;

public:
    ConfigurationItem(const string& t, const string& n)
        : type(t), name(n) {}

    void addAttribute(const string& key, const string& value) {
        attributes[key] = value;
    }

    string getAttribute(const string& key) const {
        auto it = attributes.find(key);
        return (it != attributes.end()) ? it->second : "";
    }

    string getType() const override { return type; }
    string getName() const override { return name; }
};

// EC2 Instance Configuration
class EC2InstanceConfig : public ConfigurationItem {
public:
    EC2InstanceConfig(const string& name)
        : ConfigurationItem("aws_instance", name) {}

    bool validate() const override {
        vector<string> violations;

        // Critical EC2 Security Checks
        if (getAttribute("vpc_security_group_ids").empty()) {
            violations.push_back("EC2 instance must be associated with a security group");
        }
        if (getAttribute("associate_public_ip_address") == "true") {
            violations.push_back("Public IP addresses should be avoided unless necessary");
        }
        if (getAttribute("root_block_device.encrypted") != "true") {
            violations.push_back("Root volume must be encrypted");
        }
        if (getAttribute("metadata_options.http_tokens") != "required") {
            violations.push_back("IMDSv2 must be required (http_tokens = required)");
        }
        if (getAttribute("monitoring") != "true") {
            violations.push_back("Detailed monitoring should be enabled");
        }
        
        // Report violations
        if (!violations.empty()) {
            cout << "\nViolations for EC2 Instance " << getName() << ":\n";
            for (const auto& violation : violations) {
                cout << "- " << violation << "\n";
            }
        }
        return violations.empty();
    }
};

// S3 Bucket Configuration
class S3BucketConfig : public ConfigurationItem {
public:
    S3BucketConfig(const string& name)
        : ConfigurationItem("aws_s3_bucket", name) {}

    bool validate() const override {
        vector<string> violations;

        // Critical S3 Security Checks
        if (getAttribute("acl") == "public-read" || getAttribute("acl") == "public-read-write") {
            violations.push_back("Bucket should not be publicly readable or writable");
        }
        if (getAttribute("versioning.enabled") != "true") {
            violations.push_back("Versioning must be enabled");
        }
        if (getAttribute("server_side_encryption_configuration").empty()) {
            violations.push_back("Server-side encryption must be configured");
        }
        if (getAttribute("logging").empty()) {
            violations.push_back("Access logging should be enabled");
        }
        if (getAttribute("public_access_block").empty()) {
            violations.push_back("Public access block configuration must be set");
        }

        // Report violations
        if (!violations.empty()) {
            cout << "\nViolations for S3 Bucket " << getName() << ":\n";
            for (const auto& violation : violations) {
                cout << "- " << violation << "\n";
            }
        }
        return violations.empty();
    }
};

// RDS Instance Configuration
class RDSInstanceConfig : public ConfigurationItem {
public:
    RDSInstanceConfig(const string& name)
        : ConfigurationItem("aws_db_instance", name) {}

    bool validate() const override {
        vector<string> violations;

        // Critical RDS Security Checks
        if (getAttribute("storage_encrypted") != "true") {
            violations.push_back("Storage encryption must be enabled");
        }
        if (getAttribute("publicly_accessible") == "true") {
            violations.push_back("Database must not be publicly accessible");
        }
        if (getAttribute("backup_retention_period") == "0") {
            violations.push_back("Backup retention must be configured");
        }
        if (getAttribute("deletion_protection") != "true") {
            violations.push_back("Deletion protection should be enabled");
        }
        if (getAttribute("skip_final_snapshot") == "true") {
            violations.push_back("Final snapshot should not be skipped");
        }

        // Report violations
        if (!violations.empty()) {
            cout << "\nViolations for RDS Instance " << getName() << ":\n";
            for (const auto& violation : violations) {
                cout << "- " << violation << "\n";
            }
        }
        return violations.empty();
    }
};

// VPC Configuration
class VPCConfig : public ConfigurationItem {
public:
    VPCConfig(const string& name)
        : ConfigurationItem("aws_vpc", name) {}

    bool validate() const override {
        vector<string> violations;

        // Critical VPC Security Checks
        if (getAttribute("enable_dns_hostnames") != "true") {
            violations.push_back("DNS hostnames should be enabled");
        }
        if (getAttribute("enable_dns_support") != "true") {
            violations.push_back("DNS support should be enabled");
        }
        if (getAttribute("instance_tenancy") == "default") {
            violations.push_back("Consider using dedicated tenancy for sensitive workloads");
        }
        if (getAttribute("flow_log_config").empty()) {
            violations.push_back("VPC flow logs should be enabled");
        }

        // Report violations
        if (!violations.empty()) {
            cout << "\nViolations for VPC " << getName() << ":\n";
            for (const auto& violation : violations) {
                cout << "- " << violation << "\n";
            }
        }
        return violations.empty();
    }
};

// Security Group Configuration
class SecurityGroupConfig : public ConfigurationItem {
public:
    SecurityGroupConfig(const string& name)
        : ConfigurationItem("aws_security_group", name) {}

    bool validate() const override {
        vector<string> violations;

        // Critical Security Group Checks
        if (getAttribute("description").empty()) {
            violations.push_back("Security group must have a description");
        }

        // Check for dangerous ingress rules
        string ingressRules = getAttribute("ingress");
        if (ingressRules.find("0.0.0.0/0") != string::npos) {
            violations.push_back("Security group has overly permissive inbound rules (0.0.0.0/0)");
        }
        if (ingressRules.find("port = 22") != string::npos &&
            ingressRules.find("0.0.0.0/0") != string::npos) {
            violations.push_back("SSH (port 22) should not be open to the world");
        }
        if (ingressRules.find("port = 3389") != string::npos &&
            ingressRules.find("0.0.0.0/0") != string::npos) {
            violations.push_back("RDP (port 3389) should not be open to the world");
        }

        // Report violations
        if (!violations.empty()) {
            cout << "\nViolations for Security Group " << getName() << ":\n";
            for (const auto& violation : violations) {
                cout << "- " << violation << "\n";
            }
        }
        return violations.empty();
    }
};

class IAMUserConfig : public ConfigurationItem {
public:
    IAMUserConfig(const string& name)
    : ConfigurationItem("aws_iam_user", name) {}

    bool validate() const override {
        vector<string> violations;

        // Critical IAM User Security Checks
        if (getAttribute("password_reset_required") != "true") {
            violations.push_back("Users should be required to reset password on first login");
        }
        if (getAttribute("force_destroy") == "true") {
            violations.push_back("Force destroy should be disabled to prevent accidental user deletion");
        }

        // Check for console access without MFA
        if (getAttribute("console_access") == "true" &&
            getAttribute("mfa_enabled") != "true") {
            violations.push_back("Console access requires MFA configuration");
            }

            // Check for programmatic access configuration
            string accessKeys = getAttribute("access_key");
        if (!accessKeys.empty() && getAttribute("pgp_key").empty()) {
            violations.push_back("Access keys should be encrypted with a PGP key");
        }

        // Check for direct policy attachments
        if (!getAttribute("policy_arns").empty()) {
            violations.push_back("Avoid attaching policies directly to users, use groups instead");
        }

        // Report violations
        if (!violations.empty()) {
            cout << "\nViolations for IAM User " << getName() << ":\n";
            for (const auto& violation : violations) {
                cout << "- " << violation << "\n";
            }
        }
        return violations.empty();
    }
};

// IAM Role Configuration
class IAMRoleConfig : public ConfigurationItem {
public:
    IAMRoleConfig(const string& name)
    : ConfigurationItem("aws_iam_role", name) {}

    bool validate() const override {
        vector<string> violations;

        // Critical IAM Role Security Checks
        if (getAttribute("description").empty()) {
            violations.push_back("Role should have a description for audit purposes");
        }

        // Check assume role policy
        string assumeRolePolicy = getAttribute("assume_role_policy");
        if (assumeRolePolicy.find("Principal") == string::npos) {
            violations.push_back("Role must specify a principal in assume role policy");
        }
        if (assumeRolePolicy.find("*") != string::npos) {
            violations.push_back("Wildcard (*) principals should be avoided in assume role policy");
        }

        // Check maximum session duration
        string maxSessionDuration = getAttribute("max_session_duration");
        if (!maxSessionDuration.empty()) {
            try {
                int duration = stoi(maxSessionDuration);
                if (duration > 43200) { // 12 hours in seconds
                    violations.push_back("Session duration should not exceed 12 hours");
                }
            } catch (...) {
                violations.push_back("Invalid max session duration value");
            }
        }

        // Check for permissions boundary
        if (getAttribute("permissions_boundary").empty()) {
            violations.push_back("Consider setting a permissions boundary for additional security");
        }

        // Check attached policies
        string attachedPolicies = getAttribute("managed_policy_arns");
        if (attachedPolicies.find("arn:aws:iam::aws:policy/AdministratorAccess") != string::npos) {
            violations.push_back("Avoid using AdministratorAccess policy, follow least privilege principle");
        }

        // Report violations
        if (!violations.empty()) {
            cout << "\nViolations for IAM Role " << getName() << ":\n";
            for (const auto& violation : violations) {
                cout << "- " << violation << "\n";
            }
        }
        return violations.empty();
    }
};

// IAM Policy Configuration
class IAMPolicyConfig : public ConfigurationItem {
public:
    IAMPolicyConfig(const string& name)
    : ConfigurationItem("aws_iam_policy", name) {}

    bool validate() const override {
        vector<string> violations;

        // Critical IAM Policy Security Checks
        if (getAttribute("description").empty()) {
            violations.push_back("Policy should have a description for audit purposes");
        }

        // Check policy document
        string policyDocument = getAttribute("policy");
        if (policyDocument.find("Effect\": \"Allow\"") != string::npos &&
            policyDocument.find("Resource\": \"*\"") != string::npos) {
            violations.push_back("Avoid using wildcard (*) in resource field with Allow effect");
            }
            if (policyDocument.find("Action\": \"*\"") != string::npos ||
                policyDocument.find("NotAction\"") != string::npos) {
                violations.push_back("Avoid using wildcard (*) actions or NotAction");
                }

                // Check for sensitive service access
                vector<string> sensitiveServices = {
                    "iam:", "organizations:", "kms:", "secretsmanager:"
                };
            for (const auto& service : sensitiveServices) {
                if (policyDocument.find(service) != string::npos) {
                    violations.push_back("Policy grants access to sensitive service: " + service);
                }
            }

            // Report violations
            if (!violations.empty()) {
                cout << "\nViolations for IAM Policy " << getName() << ":\n";
                for (const auto& violation : violations) {
                    cout << "- " << violation << "\n";
                }
            }
            return violations.empty();
    }
};

// Update the ConfigurationFactory to include new IAM types
class ConfigurationFactory {
public:
    static unique_ptr<ConfigurationItem> createConfig(const string& type, const string& name) {
        if (type == "aws_instance") {
            return make_unique<EC2InstanceConfig>(name);
        } else if (type == "aws_s3_bucket") {
            return make_unique<S3BucketConfig>(name);
        } else if (type == "aws_db_instance") {
            return make_unique<RDSInstanceConfig>(name);
        } else if (type == "aws_vpc") {
            return make_unique<VPCConfig>(name);
        } else if (type == "aws_security_group") {
            return make_unique<SecurityGroupConfig>(name);
        } else if (type == "aws_iam_user") {
            return make_unique<IAMUserConfig>(name);
        } else if (type == "aws_iam_role") {
            return make_unique<IAMRoleConfig>(name);
        } else if (type == "aws_iam_policy") {
            return make_unique<IAMPolicyConfig>(name);
        }
        return nullptr;
    }
};

// Class for analyzing Terraform files
class TerraformAnalyzer {
private:
    vector<unique_ptr<ConfigurationItem>> configurations;
    
    // Inside the TerraformAnalyzer class
    void parseHCL(const string& content) {
        istringstream stream(content);
        string line;
        unique_ptr<ConfigurationItem> currentConfig = nullptr;

        // Fixed regex patterns with proper escaping
        regex resourceRegex("resource\\s+\"([^\"]+)\"\\s+\"([^\"]+)\"");
        regex attributeRegex("\\s*(\\w+)\\s*=\\s*\"([^\"]*)\"");

        while (getline(stream, line)) {
            smatch matches;

            if (regex_search(line, matches, resourceRegex)) {
                if (currentConfig) {
                    configurations.push_back(move(currentConfig));
                }
                currentConfig = ConfigurationFactory::createConfig(matches[1].str(), matches[2].str());
            }
            else if (currentConfig && regex_search(line, matches, attributeRegex)) {
                currentConfig->addAttribute(matches[1].str(), matches[2].str());
            }
        }

        if (currentConfig) {
            configurations.push_back(move(currentConfig));
        }
    }

public:
    void loadFromFile(const string& filename) {
        ifstream file(filename);
        if (!file.is_open()) {
            throw runtime_error("Unable to open file: " + filename);
        }

        stringstream buffer;
        buffer << file.rdbuf();
        parseHCL(buffer.str());
    }

    void analyze() {
        int totalResources = configurations.size();
        int resourcesWithViolations = 0;

        cout << "\n=== Starting Terraform Security Analysis ===\n";
        cout << "Analyzing configurations for critical security issues...\n\n";

        for (const auto& config : configurations) {
            if (!config->validate()) {
                resourcesWithViolations++;
            }
        }

        cout << "\n=== Analysis Summary ===\n";
        cout << "Total resources analyzed: " << totalResources << "\n";
        cout << "Resources with violations: " << resourcesWithViolations << "\n";
        cout << "Compliance rate: " <<
            (totalResources > 0 ? 
                (100.0 * (totalResources - resourcesWithViolations) / totalResources) : 0) 
            << "%\n";
    }
};

int main() {
    try {
        TerraformAnalyzer analyzer;
        string filename;
        
        cout << "Enter the path to your Terraform configuration file: ";
        getline(cin, filename);

        analyzer.loadFromFile(filename);
        analyzer.analyze();
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
