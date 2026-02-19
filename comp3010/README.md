BOTSv3 Security Report: Frothly Brewing Company Attack Investigation 

Name: Tang Pak Chun 

Date: February 2025 

GitHub Link: https://github.com/Patrick-cybersec/COMP3010HK-Security-Operations-Incident-Management/edit/main/comp3010/README.md 

Video Presentation: https://www.youtube.com/watch?v=cexqLYRQPZM 

1. Introduction 

BOTSv3 is a free training dataset created by Splunk. It simulates a real cyber attack on a fake company called Frothly, which makes beer. The company has offices, computers, servers, email, and uses Amazon AWS cloud services. 

The dataset contains many different kinds of logs: 

Windows computer logs 

Linux server logs 

Network traffic 

Email messages 

AWS CloudTrail (who did what in the cloud) 

AWS S3 access logs (who read or uploaded files to storage) 

In this assignment, I worked on the 200-level questions. These questions focus mostly on problems in the AWS cloud and one question about Windows computers. My main goals were: 

Find out which people (IAM users) were using AWS 

Check if they used extra security (MFA) when logging in 

Discover when someone accidentally made a storage bucket public 

See what secret text file got uploaded after that mistake 

Find which computer was running a different version of Windows compared to others 

What I included in this report: Only data from the BOTSv3 dataset. I used Splunk on my own computer. All events are from August 2018 (the time range in the dataset). 

This exercise is very useful because it shows exactly how real Security Operations Center (SOC) analysts work every day: reading logs, asking questions, and finding problems before attackers cause big damage. 

2. SOC Teams and How to Handle Security Incidents 

A Security Operations Center (SOC) is like a control room that watches for cyber attacks 24/7. It has three main levels of people: 

Tier 1 analysts: They look at many alerts every day. They decide if something is real or just noise. They do the first quick check. 

Tier 2 analysts: They do deeper work. They search logs, connect different clues, and find out what really happened. 

Tier 3 analysts: They are experts. They hunt for hidden threats, write new detection rules, and help fix very difficult problems. 

In the BOTSv3 scenario: 

Tier 1 might see alerts about strange AWS changes or many failed logins. 

Tier 2 would use Splunk to search for the exact event (like PutBucketAcl) and find user “bstoll” did it. 

Tier 3 would look at the whole picture and suggest long-term fixes like better AWS settings or new alerts. 

Most SOCs follow the NIST incident response steps: 

Preparation — Buy good tools, train people, make playbooks 

Detection and Analysis — Find bad activity fast using logs and alerts 

Containment — Stop the attack from spreading (example: make bucket private again) 

Eradication — Remove the problem completely 

Recovery — Bring systems back to normal 

Post-Incident — Write a report and improve everything 

From BOTSv3 I learned important lessons: 

Many security problems start because normal employees make mistakes (like forgetting to secure a bucket). 

If logs are missing or hard to search, it takes much longer to find the fact. 

Companies should use automatic tools (such as SOAR) to react faster and reduce human work. 

Prevention is better than reaction — strong rules like force MFA and never allow public buckets can stop most accidents. 

3. How I Installed Splunk and Added the Data 

I installed Splunk directly on my Windows computer (no virtual machine needed). This made setup faster and simpler for me. 

Step-by-step what I did: 

Downloaded the free Splunk Enterprise installer from the official Splunk website. 

Ran the installer and followed the wizard (chose default options). 

Started Splunk and changed the default password for safety. 

Opened the Splunk web page in my browser. 

Downloaded the BOTSv3 dataset zip file from GitHub. 

Unzipped the file. 

Used Splunk's "Add Data" feature or copied the extracted files into the correct Splunk apps folder (following the GitHub instructions). 

Restarted Splunk if needed. 

Tested with a simple search: index=botsv3 | stats count by sourcetype — it showed many sourcetypes like aws:cloudtrail, winhostmon, etc. 

Why I chose this setup: 

It is quick and easy — no need to set up a separate virtual machine. 

Works well on my personal computer without extra RAM or disk space. 

Still gives full access to all BOTSv3 data and Splunk features. 

In a real small team or student lab, many people use Windows for simplicity. 

Screenshots: 

Splunk welcome screen after login 

 

List of all sourcetypes found 

 

Simple search result showing data is working 

 

4. Answers to the 200-level Questions 

Question 1: Which IAM users used AWS services? 

Answer: bstoll,btun,splunk_access,web_admin 

Search used: index=botsv3 sourcetype=aws:cloudtrail | stats count by userIdentity.userName | sort userIdentity.userName 

 

 

Pay attention to userName 

 

Why it matters: In a real company, SOC must watch who is using cloud accounts. Strange users or too many actions can be signs of hacking. 

Question 2: Which field shows if someone did NOT use MFA? 

Answer: userIdentity.sessionContext.attributes.mfaAuthenticated 

 

 

Pay attention at mfaAuthenticated 

 

 

MfaAuthentication: false 

Why it matters: Without MFA, stolen passwords are very dangerous. SOC should make an alert for any important action done without MFA. 

Question 3: What CPU model is on the web servers? 

Answer: E5-2676 

 

 

Why it matters: Knowing normal hardware helps SOC notice strange things, for example if CPU usage suddenly goes very high because of malware. 

Question 4: What is the Event ID that made the S3 bucket public? 

Answer: ab45689d-69cd-41e7-8705-5350402cf7ac 

 

 

Pay attention at /AllUsers 

Why it matters: This ID proves exactly when and how the security mistake happened. 

Question 5: What is Bud’s username? 

Answer: bstoll 

 

Why it matters: We can see it was probably an accident by an employee, not an outside hacker. 

Question 6: What is the name of the public S3 bucket? 

Answer: frothlywebcode 

 

 

Pay attention at bucketName 

Why it matters: Knowing the exact bucket name helps understand how much data was at risk. 

Question 7: What text file was uploaded when the bucket was public? 

Answer: OPEN_BUCKET_PLEASE_FIX.txt 

 

 

Why it matters: This shows attackers (or curious people) could download secret files very easily after the mistake. 

Question 8: Which computer has a different Windows version? 

Answer: bstoll-l.froth.ly 

 

Pay attention at OS=”Microsoft Windows 10 Enterprise” 

Other hosts using Microsoft Windows 10 Pro, but host: BSTOLL-L is uniquely using Microsoft Windows 10  Enterprise version. 

 

Why it matters: Different versions can be a sign of compromise, or just bad management — SOC should check both. 

Overall lesson: One small human mistake can cause big data leaks. Good tools like Splunk + strong rules can catch and stop it early. 

5. Conclusion and References 

Summary of what I found: 

User bstoll made a storage bucket public by accident. 

After that, a sensitive text file was uploaded. 

Some AWS actions happened without MFA protection. 

One computer (bstoll-l.froth.ly) had a different Windows edition. 

What companies should improve: 

Force MFA on all accounts 

Use AWS setting to block public buckets automatically 

Create alerts for dangerous events like PutBucketAcl with public access 

Keep a list of normal computer setups so strange ones are easy to notice 

Simple references: 

NIST. Computer Security Incident Handling Guide. 2012. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf  

Splunk. BOTSv3 Dataset on GitHub. https://github.com/splunk/botsv3  

AWS. Explanation of PutBucketAcl. https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html 

Extra files:  

Screenshots folder with pictures from Splunk  

Video showing live searches and explanations 

 

Gernerative AI Declaration 

I applied AI when i: 

-Tell my answer to ai and let it generates a report with professional and neatly format. 

-troubleshoot at finding the answer of question8. I asked ai and know that the operating system field is shown as “operatingsystem” at splunk and computer name as “computername”. 

-ask ai to check if i am missing component of submitting the coursework. 

 
