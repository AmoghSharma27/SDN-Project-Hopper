

# Author: Miriam Okutuo
# Date: 20-03-2026
# @brief: This file cleans auth data and makes it scapy-ready to be parsed as packets
# sample data: 1,C2694$@DOM1,C2694$@DOM1,C2695,C528,Kerberos,Network,LogOn,Success
# where: “time,source user@domain,destination user@domain,source computer,destination computer,authentication type,logon type,authentication orientation,success/failure



paths = []

for i in range (0, 1):
    # with open("auth/authx00") as data_file:
    # file_name = f"auth/authx{str(i).zfill(2)}"
    file_name = f"data/authx00"
    with open(file_name) as data_file:
        for data in data_file:
            row = data.strip().split(",")

            if len(row) < 9:
                continue

            # we're interested in time, src_user, dst_user, src_host and dest_host. 
            # we filter using auth i.e LogOn or LogOff and status i.e Success of Failure
            time = int(row[0])
            src_user = row[1]
            dst_user = row[2]
            src_host = row[3]
            dst_host = row[4]
            auth = row[7]
            status = row[8]

            if auth == "LogOn" and status == "Success":

                # also filter out anonymous (carries no credential identity) and self logins
                if src_user.startswith("ANONYMOUS") or dst_user.startswith("ANONYMOUS") or src_host == dst_host: 
                    continue

                else:
                    paths.append((time, src_user, dst_user, src_host, dst_host))


def get_paths():
    return paths

# for path in paths[:10]:
#     print(path)