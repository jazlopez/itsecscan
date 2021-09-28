#!groovy
/**
 * Improvements:
 * pipelineconfig.netsparker convert to only netsparker_args
 */
@Library('depl@v1') _ // Library reference, notice the underscore
import com.thermofisher.utils.DECPUtils

def scanPayload = [
        TargetUri: '',
        ExcludeLinks: true,
        ExcludedLinks: [
                [RegexPattern: '(log|sign)\\-?(out|off)']
        ],
        MaxScanDuration: null,
        FormAuthenticationSettingModel: [
                LoginFormUrl: '',
                Personas: [
                        [IsActive: true, Password: '', UserName: '']
                ],
                DefaultPersonaValidation: true,
                DisableLogoutDetection: true,
                IsEnabled: true,
                OverrideTargetUrl: false,
                PersonasValidation: true
        ],
        CrawlAndAttack: true,
        FindAndFollowNewLinks: false,
        PolicyId: '010c4f1a1f9645f80053a89b0232a610',
        Scope: null,
]

def pipelineConfig = [
    netsparker: [
        userId: '',
        token: '',
        scanQuery: scanPayload
    ]
]

pipeline {
    agent any

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
    environment {
        USER_ID = credentials("ns_userId")
        TOKEN = credentials("ns_token")
    }
    stages {
        stage("Security Netsparker Scan") {
            steps{
                script {

                    // validations and clean up
                    params.URI_PATH = !params.URI_PATH ? "/" : params.URI_PATH.trim()
                    params.FORM_LOGIN_USERNAME = params.FORM_LOGIN_USERNAME.trim()

                    // validate scan duration
                    if(!number.isInteger(params.MAX_DURATION_SCAN)) {
                        throw Exception('MAX_DURATION_SCAN needs to be an integer')
                    }

                    _maxDurationScan = params.MAX_DURATION_SCAN as int
                    if(!_maxDurationScan >= 0) {
                        throw Exception('MAX_DURATION_SCAN needs to be equal or greater than 0')
                    }

                    // netspark credentials
                    pipelineConfig.netsparker.userId = env.USER_ID
                    pipelineConfig.netsparker.token = env.TOKEN
                    pipelineConfig.netsparker.scanQuery.TargetUri = params.TARGET_URI + params.URI_PATH
                    pipelineConfig.netsparker.MaxScanDuration = _maxDurationScan

                    // does it require login?
                    if(params.FORM_LOGIN_USERNAME) {
                        pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.LoginFormUrl = params.TARGET_URI
                        pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.Personas[0].UserName = params.FORM_LOGIN_USERNAME
                        pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.Personas[0].Password = params.FORM_LOGIN_PASSWORD
                    }

                    // print out confirmation data
                    println(pipelineConfig)
                    // netsparkerSecurityScan(pipelineConfig.netsparker)
                }
            }
        }
    }
}
