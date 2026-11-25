import type { Check, Finding, Patch } from "../types.js";
import { DOC_EXT, serverShape } from "../util.js";

const SG_PATH = "infra/security-group.yaml";
const UFW_PATH = "infra/ufw.sh";
const SG_RE = /AWS::EC2::SecurityGroup/;
const UFW_RE = /ufw /;

const SG_YAML = `AWSTemplateFormatVersion: "2010-09-09"
Description: Security group for the app: HTTPS and HTTP ingress only, no SSH.

Parameters:
  VpcId:
    Type: AWS::EC2::VPC::Id
    Description: VPC to place the security group in

Resources:
  AppSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow HTTPS 443 and HTTP 80 from anywhere; SSH stays closed
      VpcId: !Ref VpcId
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
      SecurityGroupEgress:
        - IpProtocol: "-1"
          CidrIp: 0.0.0.0/0
`;

const UFW_SH = `#!/bin/sh
set -e

# Firewall baseline: deny incoming, allow outgoing, open only HTTP 80/tcp and HTTPS 443/tcp.
# SSH (port 22) stays closed. To allow SSH from one IP only, run before enabling:
#   ufw allow from <IP> to any port 22

ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
`;

export const firewallRules: Check = {
  id: "firewall-rules",
  group: "C-security",
  title: "No firewall rules defined",
  severity: "medium",
  mode: "template",

  skip({ repo }) {
    const s = serverShape(repo.files);
    return s.node || s.python || s.container
      ? null
      : "No long-running server found. Static and serverless hosts manage the network in front of your code.";
  },

  detect({ repo }): Finding[] {
    const hasSgFile = repo.files.some((f) => f.path === SG_PATH);
    const hasSgOrUfw = repo.files.some((f) => !DOC_EXT.test(f.path) && (SG_RE.test(f.content) || UFW_RE.test(f.content)));
    if (hasSgFile || hasSgOrUfw) return [];
    return [{
      checkId: "firewall-rules",
      title: "No firewall rules defined",
      severity: "medium",
      file: SG_PATH,
      explanation: "No security group or UFW rules were found. Siidekick creates `infra/security-group.yaml` and `infra/ufw.sh` as templates; Siidekick never applies them — the owner reviews and runs them.",
    }];
  },

  fix({ repo }): Patch | null {
    const hasSgFile = repo.files.some((f) => f.path === SG_PATH);
    const hasSgOrUfw = repo.files.some((f) => !DOC_EXT.test(f.path) && (SG_RE.test(f.content) || UFW_RE.test(f.content)));
    if (hasSgFile || hasSgOrUfw) return null;
    return {
      id: "firewall-rules-1",
      checkId: "firewall-rules",
      title: "Add firewall rule templates",
      class: "additive",
      reason: "Adds a CloudFormation security group (HTTPS/HTTP ingress, all egress, no SSH) and a UFW script as templates for the owner to review and apply.",
      edits: [
        { kind: "create", path: SG_PATH, content: SG_YAML },
        { kind: "create", path: UFW_PATH, content: UFW_SH },
      ],
    };
  },
};
