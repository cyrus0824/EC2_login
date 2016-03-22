#!/usr/bin/env python
from boto import ec2
import sys
import json
import os
import argparse

#AWS_REGIONS = ["us-east-1","us-west-2","us-west-1","eu-west-1",
#               "eu-central-1","ap-southeast-1","ap-northeast-1",
#               "ap-northeast-2","ap-southeast-2","sa-east-1",
#               "us-gov-west-1","cn-north-1"]
AWS_REGIONS = ["us-east-1","us-west-2","us-west-1"]

PEMS_DIR = os.path.join(os.path.expanduser("~"), "pems")

class AWSConnection:
    def __init__(self):
        pass

    def get_all_profile_keys(self):
        try:
            pk_dict = json.load(open(os.path.join(os.path.expanduser("~"), ".aws_keys"), "r")) 
        except IOError:
            raise SetupException("Can't load .aws_keys in home directory")
        
        return pk_dict

    def get_connection(self, kd, r):
        try:
            conn = ec2.connect_to_region(r,
                aws_access_key_id = kd['aws_access_key_id'],
                aws_secret_access_key = kd['aws_secret_access_key'])
        except:
            raise SetupException("Can't connect to region {}".format(r))

        return conn

    def get_all_connectable_instances(self, refresh=False):
        if not refresh:
            try:
                return json.load(open(os.path.join(os.path.expanduser("~"), ".aws_instances"), "r"))
            except:
                pass

        instances = {}
        for (profile_name, key_dict) in self.get_all_profile_keys().items():
            instances[profile_name] = {}
            for region in AWS_REGIONS:
                try:
                    conn = self.get_connection(key_dict, region)
                except SetupException:
                    continue
                if not conn:
                    continue
                instances[profile_name][region] = {}
                try:
                    reservations = conn.get_all_reservations()
                except:
                    continue
                for instance in reservations:
                    if (('Name' not in instance.instances[0].tags) 
                        or (instance.instances[0].state != 'running') 
                        or not instance.instances[0].ip_address 
                        or not os.path.exists(os.path.join(PEMS_DIR, instance.instances[0].key_name + '.pem'))):
                        continue
                    instances[profile_name][region][instance.instances[0].tags['Name']] = {
                                                    "ip_address": instance.instances[0].ip_address,
                                                    "key_name": instance.instances[0].key_name
                                                    }
        with open(os.path.join(os.path.expanduser("~"), ".aws_instances"), "w") as write_file:
            json.dump(instances, write_file)
        return instances

    def get_names_dict(self):
        names = {}
        i = self.get_all_connectable_instances()
        for (profile, p_dict) in i.items():
            for (region, r_dict) in p_dict.items():
                for (iname, i_dict) in r_dict.items():
                    names.setdefault(iname, []).append( (profile, region) )
        return names

    def get_name_info(self):
        info = {}
        i = self.get_all_connectable_instances()
        for (profile, p_dict) in i.items():
            for (region, r_dict) in p_dict.items():
                for (iname, i_dict) in r_dict.items():
                    info[iname] = i_dict
        return info

class SetupException(BaseException):
    pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="instance name to connect to", nargs="?")
    parser.add_argument("-l", "--ls", help="list connectable instance names",
                    action="store_true")
    parser.add_argument("-r", "--refresh", help="refresh connectable instance names",
                    action="store_true")
    args = parser.parse_args()
    
    aws = AWSConnection()

    if args.ls:
        print("AVAILABLE EC2 INSTANCES\n**********************\n" + "\n".join(aws.get_name_info().keys()))
    elif args.refresh:
        u = aws.get_all_connectable_instances(refresh=True)
        u = None
    else:
        if args.name:
            # Could check for name conflicts here.
            try:
                ip_address = aws.get_name_info()[args.name]['ip_address']
                key_file = os.path.join(PEMS_DIR, aws.get_name_info()[args.name]['key_name'] + '.pem')
            except:
                raise SetupException("Couldn't find instance named {}.  Available instances are:\n".format(args.name) + "\n".join(aws.get_names_dict().keys()) + "\nCheck the name or try to refresh using ec_login --refresh")
            os.system("ssh -i {} -o StrictHostKeyChecking=no ubuntu@{}".format(key_file, ip_address))
            return
        else:
            print("\nArguments required.  Use ec_login --help for more information.")
    return

if __name__ == "__main__":
    main()
