### ITSECSCAN

Launch security scans by netsparker cloud with custom arguments.

#### ABSTRACT

This effort is an continuation of disassociation of the security scan from the main build deployment procedure. In the past, it was only possible to run security 
scans at the time of code deployments which it was not practical since it blocks the ability to create an audit security report at any time.

After it is disassociated from the deploy building process is possible to run any security scans from any url as wish it. 

The jenkinsfile in this project is its project by itself and it can be registered in jenkins instance and run it as standalone.

#### ARGUMENTS

The jenkinsfile it now enables end user to have fine granular control of the scan options as they are no longer hardcoded
but it is possible for users to enter duration of scans, type of scope, authentication user name and password whether it applies for the scan.

The body of the arguments for security scan now looks as is:

```groovy
parameters {
        choice(name: 'TARGET_URI', description: 'Host domain of security scan',
                choices: [
                        'https://test.apps.thermofisher.com',
                        'https://stage.apps.thermofisher.com',
                        'https://stage.apps.thermofisher.com.cn'
                ]
        )

        string(name: 'URI_PATH',
                defaultValue: '/',
                description: 'Path and query string of the scan URL .e.g. /api/v1/auth?q=v)')

        choice(name:'SCOPE', description: 'Scope of security scan. Example' +
                'Given scan url http://kiwis.org/foo' +
                'EnteredPathAndBelow: will scan given url and anything that matches under the given path: e.g /foo/[bar|baz]/?q=v' +
                'OnlyEnteredUrl: will scan given url and anything that start with same url: e.g. /foo.aspx, foo.html, foo?q=v' +
                'WholeDomain: will scan the top level domain and all its assets. e.g. http://kiwis.org/[foo|bar|baz|info|docs]?q=v',
                choices: [
                        'EnteredPathAndBelow',
                        'OnlyEnteredUrl',
                        'Whole Domain'
                ]
        )

        string(name: 'MAX_DURATION_SCAN', description: 'Scan maximum duration. Leave it empty for no maximum limit',
                defaultValue: '1')

        string(name: 'FORM LOGIN USERNAME',
                defaultValue: '',
                description: 'Provide authentication username (leave it empty if login is not required)'
        )

        password(name: 'FORM LOGIN PASSWORD',
                defaultValue: '',
                description: 'Provide authentication password (leave it empty if not login is required)'
        )
    }

```

#### TODO

- complete documentation of first initial iteration

#### VERSION

1.0.0 Initial version
