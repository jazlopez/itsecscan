#!groovy
/**
 * Improvements:
 * pipelineconfig.netsparker convert to only netsparker_args
 @Library('depl@v1') _ // Library reference, notice the underscore
 import com.thermofisher.utils.DECPUtils
**/

def scanPayload = [
        TargetUri: '',
        excludedLinks: false,
        excludeLinks: [],
        MaxScanDuration: 48,
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
                        'https://stage-api.thermofisher.com',
                        'https://kong-proxy.tfctest.thermofisher.net',
                        'https://kong-proxy.tfcstage.thermofisher.net',
                        'https://test.apps.thermofisher.com',
                        'https://stage.apps.thermofisher.com',
                        'https://stage-api.thermofisher.com.cn',
                        'https://stage.apps.thermofisher.com.cn'
                ]
        )

        string(name: 'URI_PATH',
                defaultValue: '/',
                description: 'Path and query string of the scan URL .e.g. /api/v1/auth?q=v)') // end of uri path

        text(name: 'INCLUDE_URI_PATH', defaultValue: '', description: 'List of must-include URLs in scan. One per line.' +
                     '<br/>Notice: there is not validation of badformed URLs<br/>')

        text(name: 'EXCLUDE_URI_PATH', defaultValue: '', description: 'List of must-exclude URLs in scan. One per line.' +
                     '<br/>Notice: there is not validation of badformed URLs<br/>')

        choice(name:'SCOPE', description: 'Scope of security scan. Example' +
                'Given scan url http://kiwis.org/foo' +
                '<b>EnteredPathAndBelow</b>: will scan given url and anything that matches under the given path: e.g /foo/[bar|baz]/?q=v<br>' +
                'OnlyEnteredUrl: will scan given url and anything that start with same url: e.g. /foo.aspx, foo.html, foo?q=v</br/>' +
                'WholeDomain: will scan the top level domain and all its assets. e.g. http://kiwis.org/[foo|bar|baz|info|docs]?q=v<br/>',
                choices: [
                        'EnteredPathAndBelow',
                        'OnlyEnteredUrl',
                        'Whole Domain'
                ]
        ) // end of scope

        string(name: 'MAX_DURATION_SCAN', description: 'Scan maximum duration. Leave it empty for no maximum limit',
                defaultValue: '1') // end of max duration scan

        string(name: 'FORM_LOGIN_USERNAME',
                defaultValue: '',
                description: 'Provide authentication username (leave it empty if login is not required)'
        ) // end of login username

        password(name: 'FORM_LOGIN_PASSWORD',
                defaultValue: '',
                description: 'Provide authentication password (leave it empty if not login is required)'
        ) // end of login password

    } // end of arguments

    environment {
        // USER_ID = credentials("ns_userId")
        // TOKEN = credentials("ns_token")
        USER_ID = 'b6d88c57a15441bcb67daa7004a5dd98'
        TOKEN = 'cyWPzFmaWZIFGU/zSVmLWCd2jnRPXkKp9VVbOB4thn4='
    } // end of environment

    stages {
        stage("Validations") {
            steps{
                script {
                    echo '*********************** SECURITY SCAN INPUT VALIDATION ***********************'

                    // validations and clean up
                    // params.URI_PATH = !params.URI_PATH ? "/" : params.URI_PATH.trim()
                    // params.FORM_LOGIN_USERNAME = params.FORM_LOGIN_USERNAME.trim()
                    params.URI_PATH = params.URI_PATH.trim()
                    params.FORM_LOGIN_USERNAME = params.FORM_LOGIN_USERNAME.trim()
                    params.INCLUDE_URI_PATH = params.INCLUDE_URI_PATH.trim()
                    params.EXCLUDE_URI_PATH = params.EXCLUDE_URI_PATH.trim()
                    params.MAX_DURATION_SCAN = params.MAX_DURATION_SCAN.trim()
                    

                    // if(params.INCLUDE_URI_PATH) {
                    //     pipelineConfig.netsparker.scanQuery.ImportLinks = true
                    //     pipelineConfig.netsparker.scanQuery.ImportedLinks = INCLUDE_URI_PATH.split('\n').collect{it}
                    // }
 
                    if(params.EXCLUDE_URI_PATH) {
                        scanPayload.ExcludeLinks = true
                        scanPayload.ExcludedLinks = EXCLUDE_URI_PATH.split('\n').collect{it}
                    }
                
                    // validate scan duration
                    if(!params.MAX_DURATION_SCAN.isInteger()) {
                        throw new Exception('MAX_DURATION_SCAN needs to be an integer')
                    }

                    _maxDurationScan = params.MAX_DURATION_SCAN.toInteger()
                    
                    if(_maxDurationScan < 0) {
                         throw new Exception('MAX_DURATION_SCAN needs to be equal or greater than 0')
                    }

                    // scanPayload.TargetUri = params.TARGET_URI + params.URI_PATH
                    // scanPayload.MaxScanDuration = _maxDurationScan

                    // // does it require login?
                    // if(params.FORM_LOGIN_USERNAME) {
                    //     pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.LoginFormUrl = params.TARGET_URI
                    //     pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.Personas[0].UserName = params.FORM_LOGIN_USERNAME
                    //     pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.Personas[0].Password = params.FORM_LOGIN_PASSWORD
                    // }
                }
            }
        }

        // stage('Environment') {
        //     steps{
        //         echo '*********************** SECURITY SCAN API KEYS SETUP ***********************'
        //         script {
        //             // netspark credentials
        //             pipelineConfig.netsparker.userId = env.USER_ID
        //             pipelineConfig.netsparker.token = env.TOKEN
        //         }
        //     }
        // }

        stage('Scan') {
            steps{
                echo '*********************** SECURITY SCAN ASSETS ***********************'

                println pipelineConfig.netsparker.ImportedLinks
                // netsparkerSecurityScan(pipelineConfig.netsparker)
            }
        }
    }
}
