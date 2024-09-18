rule user_added_to_privileged_groups
{
  meta:
     subject = "user added to privileged groups"
     description = "This rule detects when a user account is added to predefined privileged user groups. Privileged groups provide elevated access and permissions to critical systems and resources. Monitoring this behaviour helps to mitigate the risk of unauthorized access to privileged groups."
     tactic = "Privilege Escalation"
     technique = "Valid Accounts"
     subtechnique = "T1078.001, T1078.002, T1078.003, T1078.004"
     tool = ""
     datasource = "User Account"
     category = ""
     product = ""
     logsource = "Operating System, Windows Events, Iaas"
     actor = ""
     malware = ""
     vulnerability = ""
     custom = ""
     confidence = "Medium"
     severity = "Medium"
     falsePositives = "This could be benign if administrator adding a user to privileged groups by adhering to change management process. Please whitelist the source IPs & users from which it is acceptable behavior."
     externalSubject = "0"
     externalMITRE = "0"
     version = "4"

  events:
        (($e.metadata.event_type = "GROUP_MODIFICATION" and
        $e.metadata.description = /added|add/ nocase ) or
        
       $e.principal.user.userid != "jayanth"
   condition:
       $e
   }
