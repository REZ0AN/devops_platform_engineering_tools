# Github Organization Repository Monthly Audit By Commits of Repository Members or Contributors

First of all download the files in this folder to you desired folder in your pc or server. Also setup the `mailx` for sending mail to distribution lists.

## Step-1 Download all the necessary required packages

```bash
pip3 install -r requirements.txt
```

## Step-2 Get your github personal access token

Get your github personal access token and make sure you have export it into your OS env variable by `GH_PAT` name.

## Step-3 Add the emails to sent audit information

Place the `emails` separated by space into the `MAILUSERS` variable in the script `audit-gen-with-mailing.sh`

## Step-4 Give the desired variables for auditing

Firstly `is_period` if you want to use duration like from start month to after two months auditing. Then set this variable `is_period` to 1 and also set the variables `MONTH_START` and `PERIOD` as well. Otherwise you want to get audit from a month range then set this variable  `is_period` to 0 and also set the variables `MONTH_START` and `MONTH_END`.

## Step-5 Give Execute permission to `audit-gen-with-mailing.sh` script

```bash
chmod +x ./audit-gen-with-mailing.sh
```
## Step-6 Execute the script

```bash
./audit-gen-with-mailing.sh
```

After a successful execution you will notice some `<Team_Name>-<Month_Start>-to-<Month_End></Month_End>-audit.csv` files in the current directory which will be sent over email to the distributions.
