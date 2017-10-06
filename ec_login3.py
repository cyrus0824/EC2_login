#!/usr/bin/env python
import boto3
import sys
import json
import os
import argparse
import glob

PEMS_DIR = os.path.join(os.path.expanduser("~"), "Dropbox", "pems")
AWS_REGIONS = ['us-west-1', 'us-west-2', 'us-east-1']

class AWSConnection:
    def __init__(self):
        pass

    def get_all_profile_keys(self):
        try:
            pk_dict = json.load(open(os.path.join(os.path.expanduser("~"), ".aws_keys"), "r")) 
        except IOError:
            raise SetupException("Can't load .aws_keys in home directory")
        
        return pk_dict

    def get_client(self, kd, r):
        try:
            client = boto3.client('ec2', aws_access_key_id = kd['aws_access_key_id'],
                        aws_secret_access_key = kd['aws_secret_access_key'], region_name=r)
        except:
            raise SetupException("Can't get client for '{}'".format(kd['aws_access_key_id']))

        return client

    def get_all_connectable_instances(self, refresh=False):
        if not refresh:
            try:
                return json.load(open(os.path.join(os.path.expanduser("~"), ".aws_instances"), "r"))
            except:
                pass

        instances = {}
        available_keypairs = [os.path.split(x)[1].split('.')[0] for x in glob.glob(os.path.join(PEMS_DIR, '*.pem'))]
        for (profile_name, key_dict) in self.get_all_profile_keys().items():
            for region in AWS_REGIONS:
                try:
                    client = self.get_client(key_dict, region)
                except SetupException:
                    continue
                     
                for reservation_instances in client.describe_instances(Filters=[
                    {'Name': 'instance-state-name', 'Values': ['running']},
                    {'Name': 'key-name', 'Values': available_keypairs},
                    {'Name': 'tag-key', 'Values': ['Name']}]).get('Reservations', []):
                    for instance_dict in reservation_instances['Instances']:
                        ip = instance_dict['PublicIpAddress']
                        user = 'ubuntu'
                        keypair = instance_dict['KeyName']
                        for tag_dict in instance_dict['Tags']:
                            if (tag_dict.get('Key', False)) and (tag_dict['Key'] == 'Name'):
                                name = tag_dict['Value']
                            if (tag_dict.get('Key', False)) and (tag_dict['Key'] == 'User'):
                                user = tag_dict['Value']
                        if name not in instances:
                            instances[name] = {'key_name': keypair, 'user': user, 'ip_address': ip}
        with open(os.path.join(os.path.expanduser("~"), ".aws_instances"), "w+") as write_file:
            json.dump(instances, write_file)
        with open(os.path.join(os.path.expanduser("~"), ".aws_autocomplete"), "w+") as write_file:
            write_file.write(" ".join(list(instances.keys())))
        return instances

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
        print("AVAILABLE EC2 INSTANCES\n**********************\n" + "\n".join(list(aws.get_all_connectable_instances().keys())))
    elif args.refresh:
        u = aws.get_all_connectable_instances(refresh=True)
        u = None
    else:
        if args.name:
            # Could check for name conflicts here.
            try:
                ti = aws.get_all_connectable_instances()[args.name]
                ip_address = ti['ip_address']
                key_file = os.path.join(PEMS_DIR, ti['key_name'] + '.pem')
                user = ti['user']
            except:
                raise SetupException("Couldn't find instance named {}.  Available instances are:\n".format(args.name) + "\n".join(list(aws.get_all_connectable_instances().keys())) + "\nCheck the name or try to refresh using ec_login --refresh")
            os.system("ssh -i {} -o StrictHostKeyChecking=no {}@{}".format(key_file, user, ip_address))
            return
        else:
            print("\nArguments required.  Use ec_login --help for more information.")
    return

if __name__ == "__main__":
    main()
