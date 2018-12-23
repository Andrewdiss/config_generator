import argparse
import boto3
import datetime
import logging
import ntpath
import os
import re
import smtplib
import sys
import torndb
# ToDO: check id 1367!!!!!!!!!!!!!!
from ConfigParser import SafeConfigParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO
from jinja2 import Template
from multiprocessing.dummy import Pool as ThreadPool
from platform import system as sys_type

DEBUG = int(os.environ.get('DEBUG', '1'))       # ToDo _____ DEFAULT SHOULD BE 0

""" ~~~~ Set Logger ~~~~ """
log_file = 'nginx_gen_{0}.log'.format(datetime.datetime.now().strftime('%Y.%m.%d-%H.%M'))
log_file = os.path.join(os.path.dirname(__file__), 'logs', log_file)

log = logging.getLogger('system')
log.setLevel(logging.INFO)

formatter = logging.Formatter('[%(asctime)s] - [%(filename)s:%(lineno)s - %(funcName)s() ] - %(message)s')
log_handler = logging.FileHandler(log_file)
log_handler.setLevel(logging.INFO)
log_handler.setFormatter(formatter)
log.addHandler(log_handler)


""" ~~~~ Process configuration settings Logger ~~~~ """
CONFIG = 'config.ini'
if DEBUG:
    CONFIG = 'stage_config.ini'

CONFIG = os.path.join(os.path.dirname(__file__), CONFIG)
conf = SafeConfigParser()
conf.read(CONFIG)


def main():
    log.info("Start updating process for nginx config files")
    provider_list = get_data_from_db()

    if provider_list:
        checked_providers = process_providers(provider_list[:10])
        valid_providers = [row for row in checked_providers if row.get('checked')]
        invalid_providers = [row for row in checked_providers if not row.get('checked')]

        # Store data into the file
        file_path = store_data(valid_providers)
        if file_path:
            s3_file_urls = []
            for file_name in file_path:
                s3_file_urls.append(aws_s3_processing(file_name))

            subject = "Nginx config: config file links"
            send_email(';\n'.join(s3_file_urls), subject) if s3_file_urls else None

            log.info("Email with config urls were successfully sent")

        else:
            log.info("No files were formed during *store_data()* method")
            raise Exception

        if invalid_providers:
            invalid_providers_list = [el for el in invalid_providers if el['status']]
            list_to_send = []
            for failed in invalid_providers_list:
                row = "provider: {name},  id: {id}, host:{host}, end_point:{end_point}".format(
                    name=failed.get('provider'),
                    id=failed.get('id'),
                    host=failed.get('host'),
                    end_point=failed.get('end_point'))
                list_to_send.append(row)

            subject = "Nginx config: failed providers list"
            send_email(';\n'.join(list_to_send), subject) if list_to_send else None

        log.info("Configs were successfully created and stored to AWS")

    else:
        log.info("Unable to get provider list from database. Check DB configurations")


def get_data_from_db():
    log.info("Getting list of providers from database")
    db = torndb.Connection(
        conf.get('db_configs', 'host'),
        conf.get('db_configs', 'db'),
        conf.get('db_configs', 'user'),
        conf.get('db_configs', 'pass'))

    query = """SELECT id as provider_id, 
                      provider as provider_name, 
                      end_point, 
                      status 
               FROM {db}.rtb_provider
               """.format(db=conf.get('db_configs', 'db'))

    result = db.query(query)
    return result if result else None


def ping_tool(host_name, call_param=None, try_count=2):
    """
    Function used to ping provider host_names and check their availability.

    In case of *multiprocessing* host_name are not just name but whole provider`s record, and ping_tool function
    :returns changed state of provider record, with extra key - *checked*

    :param host_name: highlighted providers *host* name from providers *end_point*s field.
    :param call_param: flag related to the OS system where script runs
    :param try_count: ping retries
    :return: result whether ping was successful or no
    """
    ping_result = False
    call_param = call_param if call_param else '-c'

    if isinstance(host_name, dict):
        provider_data = host_name
        try:
            log.info("==> START PROCESSING name:{}, host:{}".format(provider_data['provider_name'],
                                                                    provider_data['provider_host']))
            call_command = ('ping', call_param, '1', provider_data['provider_host'])
            provider_data['checked'] = os.system(' '.join(call_command)) == 0
            if not provider_data['checked'] and try_count > 0:
                return ping_tool(provider_data, call_param, try_count-1)
        except Exception as e:
            log.info("ERROR OCCURRED for host:{host}, \n{err}".format(host=provider_data, err=e))
        return provider_data
    else:
        try:
            call_command = ('ping', call_param, '1', host_name)
            ping_result = os.system(' '.join(call_command)) == 0
            if not ping_result and try_count > 0:
                return ping_tool(host_name, call_param, try_count-1)
        except Exception as e:
            log.info("ERROR OCCURRED for host:{host}, \n{err}".format(host=host_name, err=e))
        return ping_result


def process_providers(providers_data):
    """
    Process list of providers, highlights providers *host* from the *end_point*s.
    Add *hosts* & *checked* (ping result) to providers info.

    In case global variable USE_THREADS == True this function will process providers with
    multiprocessing logic, which make processing at least 3x times faster.

    :param providers_data: providers list of dictionaries
    :return: providers_data with *hosts* and *checked* statuses
    """
    log.info('Start processing provider list (Check if domain available)')
    regex_pattern = re.compile(r'(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*')
    call_param = "-n" if sys_type().lower() == "windows" else "-c"
    checked_dns = {}

    if MULTI_THREADS:
        pool_size = MULTI_THREADS
        pool = ThreadPool(pool_size)

        for provider in providers_data:
            try:
                provider['provider_host'] = regex_pattern.search(provider.get('end_point')).group('host')
            except AttributeError as e:
                provider['checked'] = False
                log.info("==> ERROR OCCURRED for provider: {name}, \n {err}".format(name=provider['provider_name'], err=e))

        checked_providers_data = pool.map(ping_tool, providers_data)
        pool.close()
        pool.join()
        return checked_providers_data

    else:
        for provider in providers_data:
            try:
                provider['host'] = regex_pattern.search(provider.get('end_point')).group('host')
                if checked_dns.get(provider['host']):
                    log.info('Host {} already in cache'.format(provider['host']))
                    provider['checked'] = checked_dns.get(provider['host'])
                else:
                    log.info("==> START PROCESSING name:{}, host:{}".format(provider['provider'], provider['host']))
                    provider['checked'] = ping_tool(provider['host'], call_param)
                    checked_dns['host'] = provider['checked']
            except AttributeError as e:
                provider['checked'] = False
                log.info("==> ERROR OCCURRED for provider: {name}, \n {err}".format(name=provider['provider'], err=e))
        log.info('Finish processing provider list for accessibility')

        return providers_data


def store_data(providers):
    """
    Store validated provider configs into the config file
    :param providers: List of sorted/validated (by domain) providers
    :return: path of the file which was created
    """
    log.info("Storing data into the config files")
    files_path = []
    temp_file_path = os.path.join(os.path.dirname(__file__), 'temp_files')
    timestamp = datetime.datetime.now().strftime("%m-%d_%H")

    templates = aws_s3_processing()
    for file_name, file_template in templates.iteritems():
        try:
            buffer_template = BytesIO()
            buffer_template.writelines(file_template)
            record_template = get_record_template(file_template)
            with BytesIO() as data_buffer:
                for provider in sorted(providers, key=lambda k: k['provider_id']):
                    filled_template = str(record_template % (provider))
                    data_buffer.writelines(filled_template)

                tp = Template(buffer_template.getvalue())
                output = tp.render(version=timestamp, provider_data=data_buffer.getvalue())

                file_name, extension = file_name.split('.')
                new_file_name = '.'.join([file_name+timestamp, extension])
                file_name_location = os.path.join(temp_file_path, new_file_name)

                with open(file_name_location, 'wb') as conf_file:
                    conf_file.write(output)

            log.info("Data was successfully stored into the file: {filename}".format(filename=new_file_name))
            files_path.append(file_name_location)

        except Exception as e:
            log.info("Error occurred while storing data into the file: {filename}\n{err}".format(
                filename=file_name,
                err=e))
    return files_path


def aws_s3_processing(config_file_path=None):

    log.info("Communicating to S3 bucket")
    try:
        session = boto3.Session(aws_access_key_id=conf.get('aws_config', 'aws_id'),
                                aws_secret_access_key=conf.get('aws_config', 'aws_key'))
        s3 = session.resource('s3')

        if config_file_path:
            filename = ntpath.basename(config_file_path)
            s3.Bucket(conf.get('aws_config', 'bucket_name')).put_object(Key=filename,
                                                                        Body=open(config_file_path, 'rb'),
                                                                        ACL='public-read')

            file_url = '%s/%s/%s' % (s3.meta.client.meta.endpoint_url,
                                     conf.get('aws_config', 'bucket_name'),
                                     filename)

            log.info("Data file {0} successfully stored to {1} bucket".format(filename,
                                                                              conf.get('aws_config', 'bucket_name')))
            return file_url


        else:
            bucket_obj = s3.Bucket(conf.get('aws_config', 'bucket_name'))
            nginx_conf_patterns = [obj.key for obj in bucket_obj.objects.all() if 'config_templates/pattern' in obj.key]

            if nginx_conf_patterns:
                patterns = {}
                for template_path in nginx_conf_patterns:
                    pattern_file = ntpath.basename(template_path)
                    filename = pattern_file.replace("pattern_", "")
                    file_content = bucket_obj.Object(template_path).get()['Body'].read()
                    patterns[filename] = file_content
                return patterns
            else:
                log.info("No pattern files found on S3 bucket *config_templates/* folder\n"
                         "pattern file name should start with *pattern_* ")
                raise Exception

    except Exception as e:
        log.info("Unable to establish AWS S3 connection.\n{err}".format(err=e))


def send_email(data_list, subject=None):
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject if subject else "Nginx config generator notification"
        msg['From'] = conf.get('mail_configs', 'gmail_user')
        msg['To'] = conf.get('mail_configs', 'email_receivers')

        text = MIMEText(data_list, 'plain')
        msg.attach(text)

        server = smtplib.SMTP(conf.get('mail_configs', "gmail_host"), conf.get('mail_configs', "gmail_port"))
        server.ehlo()
        server.starttls()
        server.login(conf.get('mail_configs', "gmail_user"), conf.get('mail_configs', "gmail_password"))
        server.sendmail("no-reply@imonomy.com", conf.get('mail_configs', 'email_receivers'), msg.as_string())
        server.close()
        log.info("Report emails sent successfully.")

    except Exception, err:
        log.info("Failed to send notification emails. \n{err}".format(err=err))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-mt', '--multi_threads',
                        help="Start processing with multiple threads (up to 5)",
                        type=threads_type)
    return parser.parse_args()


def threads_type(threads):
    """
    Validate script arguments
    :param threads: multiple threads expected argument
    :return: argument or exception
    """
    try:
        tr_value = int(threads)
        if 2 <= tr_value <= 5:
            return tr_value
        else:
            raise Exception
    except Exception as e:
        err_msg = "Argument should be integer value in range 2-5"
        log.warning(err_msg)
        print "\033[91m{error_message}\033[0m".format(error_message=err_msg)


def get_record_template(template):
    border_lines = []
    record_template = '\n\n'
    search_lines = template.split('\n')

    for i, line in enumerate(search_lines):
        if "RECORD_PATTERN" in line or "RECORD_PATTERN_END" in line:
            border_lines.append(i)

    for line in range(*sorted(border_lines))[1:]:
        record_template += search_lines[line].replace("#", "", 1) + '\n'

    return record_template


def remove_files(path):
    try:
        if os.path.exists(path):
            for trash in os.listdir(path):
                os.remove(os.path.join(path, trash))
    except Exception, err:
        raise Exception("func[remove_file] | failed err[{0}]".format(err))


if __name__ == '__main__':
    try:
        args = parse_args()
        MULTI_THREADS = args.multi_threads
        main()
        remove_files(path=os.path.join(os.path.dirname(__file__), 'temp_files'))
        log.info("Trash files removed")
        sys.exit()
    except Exception, err:
        log.info("Failed to create new config files!")
        remove_files(path=os.path.join(os.path.dirname(__file__), 'temp_files'))
        log.info("Trash files removed")
        sys.exit(1)

