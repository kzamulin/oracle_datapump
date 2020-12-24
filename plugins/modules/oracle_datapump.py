#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Konstantin Zamulin <konstantin.zamulin@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: oracle_datapump

short_description: Module to work with Oracle Datapump

version_added: "1.0.0"

description: Module to work with Oracle Data Pump. You can execute Oracle Data Pump export and import operations, supplying all required parameters using special arguments or using parafile. To interract with excutables (expdp and impdp) remote ORACLE_HOME or local one is required.

options:
    perform_checks:
        description: "Tell module whether to perform different checks before running datapump executables. Checks include: \n
          - check"
        required: false
        type: bool
        default: true
    oh_path:
        description: "ORACLE_HOME full path."
        required: true
        type: str
    sid:
        description: "SID of target database instance"
        required: true
        type: str
    db_user:
        description: "Database user of target database. Privileged user (e.g. SYSTEM) is required to perform checks (that are controlled by perform_checks option). \n SYSTEM user is recommended"
        required: true
        type: str
    db_password:
        description: "Database password for database user specified as db_user. "
        required: true
        type: str
        no_log: true
    command:
        description: "Oracle Data Pump executable name to be called: expdp or impdp"
        required: true
        type: str
    db_directory:
        description: "Oracle Database directory which will be used for running datapump executable as 'DIRECTORY' option."
        required: true
        type: str
    os_directory:
        description: "OS directory for Oracle Database directory.
         This option can be set to a directory in OS (e.g. /u01/backup) and based on it Database Directory will be created if does not exist in target database. \n
         Otherwise it must be same as OS directory for existing Database directory. \n This option has no effect if perform_checks set to False."
         required: false
         type: str
         default: 'unknown'
    logfile:
        description: "Logfile that will be used as LOGFILE option for datapump executable."
        required: false
        type: str
        default: datapump.log
    dumpfile:
        description: "Dumpfile that will be used as DUMPFILE option for datapump executable."
        required: false
        type: str
        default: datapump_%U.dmp
    parfile:
        description: "Full path to parfile that will be used as parfile option fir datapump executable. Checks are not performed on parfile contents. \n Mutually exclusive with options like 'tables' or 'schemas'. "
        required: false
        type: str
    schemas:
        description: "Schemas over coma that will be used as SCHEMAS option for datapump executable.\n Mutually exclusive with options like 'tables' or 'parfile'. "
        required: false
        type: str
    tables:
        description: "Tables over coma that will be used as TABLES option for datapump executable. \n Mutually exclusive with options like 'parfile' or 'schemas'."
        required: false
        type: str
    remap_schema:
        description: "In case schema name should be changed during impdp import this option ca be used. Format is same as for REMAP_SCHEMA option for impdp. \n
         Correct format: SCHEMA1:SCHEMA2,SCHEMA3:SCHEMA4 .. "
         required: false
         type: str
    remap_tablespace:
        description: "In case tablesapce should be changed during impdp import this option can be used. Format is the same as for REMAP_TABLESPACE option for impdp. \n Correct format: TS1:TS2,TS3:TS4 ..."
        required: false
        type: str


extends_documentation_fragment:
    - kzamulin.oracle.oracle_datapump

author:
    - Konstantin Zamulin (@kzamulin)
'''

EXAMPLES = r'''

# Execute expdp of schema HR. If directory, specified as db_directory does not exist, it will be created automatically..
  - name: Execute expdp of schema HR.
    oracle_datapump:
      oh_path: '/u01/app/oracle/product/12.2.0/dbhome_1'
      sid: 'valentin'
      db_user: 'system'
      db_password: 'oracle'
      db_directory: 'TEST'
      os_directory: '/u01/arch/datapump/test'
      command: 'expdp'
      schemas: 'HR'
      dumpfile: 'HR_%U.dmp'
      logfile: 'HR_export.log'

# Execute impdp of schema HR with remap_schema to HR_TEST and ignore ORA-39082 errors in output.
  - name: Execute impdp of schema HR
    oracle_datapump:
      oh_path: '/u01/app/oracle/product/12.2.0/dbhome_1'
      sid: 'valentin'
      db_user: 'system'
      db_password: 'oracle'
      db_directory: 'TEST'
      os_directory: '/u01/arch/datapump/test'
      command: 'impdp'
      schemas: 'HR'
      dumpfile: 'HR_%U.dmp'
      remap_schema: 'HR:HR_TEST'
      logfile: 'HR_import_remap.log'
    register: testout
    failed_when:
      - testout.failed == true
      - "'ORA-39082' not in testout.ora_errors"

'''

RETURN = r'''
ora_errors:
    type: str
    description: ORA- errors in datapump execution result.
    returned: in case any errors
'''

from ansible.module_utils.basic import AnsibleModule
import os
import re
import subprocess


def check_oracle_home(module):
    if not os.path.exists(module.params['oh_path']):
        module.fail_json(msg="Oracle home path '%s' not found." % module.params['oh_path'])
    if not (os.stat(module.params['oh_path']).st_uid == os.getuid()):
        module.fail_json(msg="Oracle home '%s' hs incorrect owner (must be same as ansible_user)." % module.params['oh_path'])


def check_executable(module):
    for executable in ['expdp','impdp','sqlplus']:
        executable_full_path = module.params['oh_path'] + '/bin/' + executable
        if not os.path.exists(executable_full_path):
            module.fail_json(msg="Executable '%s' not found." % executable_full_path)
        if not (os.stat(executable_full_path).st_uid == os.getuid()):
            module.fail_json(msg="Executable '%s' has incorrect owner (must be same as ansible_user)." % executable_full_path)


def parse_datapump_arguments(module):

    arguments=["directory=" + module.params['db_directory']]
    arguments.append('dumpfile=' + module.params['dumpfile'])
    arguments.append('logfile=' + module.params['logfile'])

    if module.params['schemas']:
        arguments.append('schemas=' + module.params['schemas'])
    if module.params['remap_schema']:
        arguments.append('remap_schema=' + module.params['remap_schema'])
    if module.params['remap_tablespace']:
        arguments.append('remap_tablespace=' + module.params['remap_tablespace'])

    return arguments


def run_datapump(module, result):
    if module.params['command'] not in ['impdp','expdp']:
        module.fail_json(msg="Executable '%s' is not expdp or impdp." % module.params['command'])
    argumentsList = parse_datapump_arguments(module)
    ora_env = os.environ.copy()
    ora_env["ORACLE_HOME"] = module.params['oh_path']
    ora_env["ORACLE_SID"] = module.params['sid']
    try:
        p = subprocess.Popen([module.params['oh_path'] + '/bin/' + module.params['command'], module.params['db_user'] + '/' + module.params['db_password']] + argumentsList,env=ora_env,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        (stdout,stderr) =  p.communicate()
        rc = p.returncode
        if rc != 0:
            if 'ORA-' in stderr.decode('utf-8'):
                errors=[]
                for line in stderr.decode('utf-8').splitlines():
                    if re.search('ORA-', line):
                        errors.append(line)
                result['ora_errors'] = str(errors)
                result['changed'] = True
                module.fail_json(msg="Datapump command completed with errors. Exit code: %s." % rc, **result)
            else:
                module.fail_json(msg="Datapump command completed with errors. Exit code: %s . Error: %s" % (rc,stderr.decode('utf-8')), changed=True, ora_errors=False)
    except subprocess.CalledProcessError as e:
        module.fail_json(msg="Error calling %s executable with SubprocessError exception, error is: %s:" % (module.params['command'],e), changed=True)
    else:
        module.fail_json(msg="Unhandled exception. Datapump %s command completed with errors: %s" % (module.params['command'],e), changed=True)


def run_sqlplus(module,sqlplus_script):
    ora_env = os.environ.copy()
    ora_env["ORACLE_HOME"] = module.params['oh_path']
    ora_env["ORACLE_SID"] = module.params['sid']
    try:
        p = subprocess.Popen([module.params['oh_path']+'/bin/sqlplus','-s','/ as sysdba'],env=ora_env,stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        (stdout,stderr) = p.communicate(sqlplus_script.encode('utf-8'))
        rc = p.returncode
        if rc != 0:
            module.fail_json(msg="Error executing SQL statement %s using sqlplus. " % sqlplus_script)
        stdout_lines = stdout.decode('utf-8').split("\n")

        return stdout_lines
    except subprocess.SubprocessError as e:
        module.fail_json(msg="Error calling sqlplus executable, error: %s:" % e)


def check_db_directory(module):
   sqlplus_script="""
     set verify off
     set heading off
     set feedback off
     WHENEVER SQLERROR EXIT SQL.SQLCODE;
     select directory_path from dba_directories where directory_name = '%s';
     exit
     """ % (module.params['db_directory'])

   out_lines = []
   for line in run_sqlplus(module,sqlplus_script):
    if line.strip() != '':
      out_lines.append(line)

   if len(out_lines) == 0:
       if not module.params['os_directory']:
           module.fail_json(msg="Database directory '%s' not found in database. You can set 'os_directory' parameter in your play and DB ans OS directories will be created automatically. " % module.params['db_directory'])
       else:
           return create_db_directory(module)
   else:
       datapump_directory_os_path = out_lines[0]
       if not os.path.exists(datapump_directory_os_path):
           module.fail_json(msg="OS directory '%s' specified as db_directory '%s' not found." % (datapump_directory_os_path,db_directory))
       if not (os.stat(datapump_directory_os_path).st_uid == os.getuid()):
           module.fail_json(msg="OS directory '%s' specified as db_directory '%s' exists, but has incorrect owner (must be same as ansible_user)" % (datapump_directory_os_path,module.params['db_directory']))
       if module.params['os_directory']:
           if not (datapump_directory_os_path == module.params['os_directory']):
               module.fail_json(msg="OS directory '%s' specified as db_directory '%s' exists, but do not equals one specified in os_directory option: %s. Please remove os_directory argument or set value that equals to OS directory specified for database directory." % (datapump_directory_os_path,module.params['db_directory'],module.params['os_directory']))
       return datapump_directory_os_path


def create_db_directory(module):
    if os.path.exists(module.params['os_directory']):
        if not os.stat(module.params['os_directory']).st_uid == os.getuid():
            module.fail_json(msg="os_directory %s exists, but has incorrect owner (must be same as ansible_user)" % module.params['os_directory'])
    else:
        try:
            os.mkdir(module.params['os_directory'])
        except OSError as e:
            module.fail_json(msg="Error creating directory %s: %s" % (module.params['os_directory'], e))

    sqlplus_script="""
     set verify off
     set heading off
     set feedback off
     WHENEVER SQLERROR EXIT SQL.SQLCODE;
     create or replace directory "%s" as '%s';
     exit
     """ % (module.params['db_directory'], module.params['os_directory'])
    run_sqlplus(module,sqlplus_script)

    return module.params['os_directory']


def check_schemas_option(module):
    """
    Checking if schemas specified in 'schemas' option exist for export or not already exist for import
    """

    if module.params['command'] == 'expdp':
        for schema in module.params['schemas'].split(','):
            if not check_schema(module,schema):
                module.fail_json(msg="Following schema, specified in 'schemas' option does not exist: %s" % schema)
    if module.params['command'] == 'impdp':
        if not module.params['remap_schema']:
            for schema in module.params['schemas'].split(','):
                if check_schema(module,schema):
                    module.fail_json(msg="Following schema, specified in 'schemas' already exists in database: %s. Drop it before running schema import" % schema)
        else:
            check_remap_schema_option(module)


def check_remap_schema_option(module):
    """
    Checking if 'remap_schema' option has correct syntax and whether target schema does not exist in target database.
    """

    for schema in module.params['remap_schema'].split(','):
        if ':' in schema:
            target_schema = schema.split(':')[1]
            if check_schema(module,target_schema):
                module.fail_json(msg="Following schema, specified in 'remap_schema' as target schema already exists in database: %s. Drop it before running schema import" % target_schema)
        else:
            module.fail_json(msg="option 'remap_schema' invalid syntax. Must be 'SOURCE_SCHEMA:TARGET_SCHEMA' over coma. ")


def check_schema(module, schema):
    """
    Checking if provided schema exists in target database.
    """

    sqlplus_script="""
    set verify off
    set heading off
    set feedback off
    WHENEVER SQLERROR EXIT SQL.SQLCODE;
    select username from dba_users where username = '%s';
    exit
    """ % (schema)

    out_lines = []
    for line in run_sqlplus(module,sqlplus_script):
        if line.strip() != '':
            out_lines.append(line)

    return False if len(out_lines) == 0 else True


def check_tables(module):
    """
    Checking that tables exist in target database
    """
    if module.params['command'] == 'expdp':
        out_lines = []
        for table in module.params['tables'].split(','):

            if '.' in table:
                table=table.split('.')[1]

            sqlplus_script="""
            set verify off
            set heading off
            set feedback off
            WHENEVER SQLERROR EXIT SQL.SQLCODE;
            select table_name from all_tables = '%s';
            exit
            """ % (table)

            for line in run_sqlplus(module,sqlplus_script):
                if line.strip() != '':
                    out_lines.append(line)

            if len(out_lines) == 0:
                module.fail_json(msg="Following table, specified in 'tables' option does not exist: %s" % table)
            out_lines.clear()


def check_remap_tablespace_option(module):
    """
    Checking if 'remap_tablespace' option has correct syntax and whether target tablespace exists in target database.
    """

    for tablespace in module.params['remap_tablespace'].split(','):
        if ':' in tablespace:
            target_tablespace = schema.split(':')[1]
            if not check_tablespace(module,target_tablespace):
                module.fail_json(msg="Following tablespace, specified in 'remap_tablespace' as target tablespace does not exist in database: %s. Create it before running schema import" % target_tablespace)
        else:
            module.fail_json(msg="option 'remap_tablespace' invalid syntax. Must be 'SOURCE_TABLESPACE:TARGET_TABLESPACE' over coma. ")

def check_tablespace(module, tablespace):
    """
    Checking if provided tablespace exists in target database.
    """

    sqlplus_script="""
    set verify off
    set heading off
    set feedback off
    WHENEVER SQLERROR EXIT SQL.SQLCODE;
    select tablespace_name from dba_tablespaces where tablespace_name = '%s';
    exit
    """ % (tablespace)

    out_lines = []
    for line in run_sqlplus(module,sqlplus_script):
        if line.strip() != '':
            out_lines.append(line)

    return False if len(out_lines) == 0 else True


def run_module():

    module_args = dict(
        perform_checks=dict(type='bool', required=False, default=True),
        oh_path=dict(type='str', required=True),
        sid=dict(type='str', required=True),
        db_user=dict(type='str', required=True),
        db_password=dict(type='str',required=True, no_log=True),
        command=dict(type='str', required=True, choices=['expdp','impdp']),
        db_directory=dict(type='str',required=True),
        os_directory=dict(type='str', required=False, default='unknown'),
        logfile=dict(type='str', required=False, default='datapump.log'),
        dumpfile=dict(type='str', required=False, default='datapump_%U.dmp'),
        parfile=dict(type='str', required=False),
        schemas=dict(type='str', required=False),
        tables=dict(type='str', required=False),
        remap_schema=dict(type='str', required=False),
        remap_tablespace=dict(type='str', required=False)
    )

    result = dict(
        changed=False,
        oh_path='',
        sid='',
        db_user='',
        db_password='',
        command='',
        db_directory='',
        os_directory='',
        logfile='',
        dumpfile=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        mutually_exclusive=[
            ('schemas','tables')
        ],
        required_one_of=[
            ('parfile','schemas','tables')
        ],
        supports_check_mode=False
    )

    if module.check_mode:
        module.exit_json(**result)

    result['oh_path'] = module.params['oh_path']
    result['sid'] = module.params['sid']
    result['db_user'] = module.params['db_user']
    result['db_password'] = module.params['db_password']
    result['command'] = module.params['command']
    result['db_directory'] = module.params['db_directory']
    result['logfile'] = module.params['logfile']
    result['dumpfile'] = module.params['dumpfile']

    check_oracle_home(module)
    check_executable(module)

    if module.params['perform_checks']:
        result['os_directory'] = check_db_directory(module)
    else:
        result['perform_checks'] = False
        result['os_directory'] = module.params['os_directory']

    if module.params['parfile']:
        result['parfile'] = module.params['parfile']

    if module.params['schemas']:
        if module.params['perform_checks']:
            check_schemas_option(module)
        result['schemas'] = module.params['schemas']

    if module.params['remap_schema']:
        result['remap_schema'] = module.params['remap_schema']

    if module.params['remap_tablespace']:
        if module.params['perform_checks']:
            check_remap_tablespace_option(module)
        result['remap_tablespace'] = module.params['remap_tablespace']

    if module.params['tables']:
        if module.params['perform_checks']:
            check_tables(module)
        result['tables'] = module.params['tables']

    run_datapump(module,result)
    result['changed'] = True

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
