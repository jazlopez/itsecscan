#!groovy
/**
 * Improvements:
 * pipelineconfig.netsparker convert to only netsparker_args
**/
@Library('depl@v1') _ // Library reference, notice the underscore
import com.thermofisher.utils.DECPUtils

def scanPayload = [
        TargetUri: '',
        MaxScanDuration: 48,
        FormAuthenticationSettingModel: [
                LoginFormUrl: '',
                Personas: [
                        [IsActive: true, Password: '', UserName: '']
                ],
                DefaultPersonaValidation: false,
                DisableLogoutDetection: true,
                IsEnabled: false,
                OverrideTargetUrl: false,
                PersonasValidation: false
        ],
        CrawlAndAttack: true,
        FindAndFollowNewLinks: true,
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
    
        booleanParam(name: 'CRAWL_N_ATTACK', description: 'Crawl webpage and follow links for vulnerabilities. It may take longer to complete', 
            defaultValue: true)
            
        booleanParam(name: 'FIND_FOLLOW_NEW_LINKS', description: 'Find new links and follow. It may take longer to complete.', 
            defaultValue: true)
            
        text(name: 'INCLUDE_URI_PATH', defaultValue: '', 
                description: 'List of must-include URLs in scan. One per line.' +
                     'Notice: there is not validation of badformed URLs')

        text(name: 'EXCLUDE_URI_PATH', defaultValue: '', 
                description: 'List of must-exclude URLs in scan. One per line.' +
                     'Notice: there is not validation of badformed URLs')

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

        string(name: 'MAX_DURATION_SCAN', description: 'Scan maximum duration between 1-48 hours',
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
        USER_ID = ''
        TOKEN = ''
    } // end of environment
    

    stages {
        stage("Validations") {
            steps{
                script {
                    echo '*********************** SECURITY SCAN INPUT VALIDATION ***********************'

                    // validations and clean up
                    _target_uri = params.TARGET_URI.trim()
                    _form_login_username = params.FORM_LOGIN_USERNAME.trim()
                    _form_login_password = params.FORM_LOGIN_PASSWORD
                    _uri_path = params.URI_PATH.trim()
                    _include_uri_path = params.INCLUDE_URI_PATH.trim()
                    _exclude_uri_path = params.EXCLUDE_URI_PATH.trim()
                    _max_duration_scan = params.MAX_DURATION_SCAN.trim()
                    

                    if(_include_uri_path) {
                        pipelineConfig.netsparker.scanQuery.ImportLinks = true
                        pipelineConfig.netsparker.scanQuery.ImportedLinks = _include_uri_path.split('\n').collect{it}
                        echo '- INCLUDE URI FROM SCAN: ' + pipelineConfig.netsparker.scanQuery.ImportedLinks
                    } else {
                        echo '- INCLUDE URI FROM SCAN: None'
                    }
 
                    if(_exclude_uri_path) {
                        pipelineConfig.netsparker.scanQuery.ExcludeLinks = true
                        pipelineConfig.netsparker.scanQuery.ExcludedLinks = _exclude_uri_path.split('\n').collect{it}
                        echo '- EXCLUDE URI FROM SCAN: ' + pipelineConfig.netsparker.scanQuery.ExcludedLinks
                    } else {
                        echo '- EXCLUDE URI FROM SCAN: None'
                    }
                
                    // validate scan duration
                    if(!_max_duration_scan.isInteger()) {
                        throw new Exception('MAX_DURATION_SCAN needs to be an integer')
                    }

                    _intMaxDurationScan = _max_duration_scan.toInteger()
                    
                    if(_intMaxDurationScan <= 0) {
                        throw new Exception('MAX_DURATION_SCAN needs to be greater than 0')
                    }
                    
                    if(_intMaxDurationScan > 48) {
                        throw new Exception('MAX_DURATION_SCAN cannot exceed 48 hours')
                        
                    }
                    echo '- MAX DURATION: ' + _intMaxDurationScan.toString()
                    
                    pipelineConfig.netsparker.scanQuery.Scope = params.SCOPE
                    

                    pipelineConfig.netsparker.scanQuery.TargetUri = _target_uri + _uri_path
                    pipelineConfig.netsparker.scanQuery.MaxScanDuration = _intMaxDurationScan

                    // // does it require login?
                    if(_form_login_username) {
                        pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.IsEnabled = true
                        pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.PersonaValidation = true
                        pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.DefaultPersonaValidation = true
                        pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.LoginFormUrl = _target_uri
                        pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.Personas[0].UserName = _form_login_username
                        pipelineConfig.netsparker.scanQuery.FormAuthenticationSettingModel.Personas[0].Password = _form_login_password.toString()
                        echo '- AUTHENTICATION: HTTP Basic'
                        echo '- FORM LOGIN URL: ' + _target_uri
                        echo '- FORM LOGIN USERNAME: ' + _form_login_username
                        echo '- FORM LOGIN PASSWORD: ' + _form_login_password.toString()
                    }
                    echo 'Block validations completed'
                }
            }
        }

        stage('Environment') {
            steps{
                echo '*********************** SECURITY SCAN API KEYS SETUP ***********************'
                script {
                    

                    // netspark credentials
                    pipelineConfig.netsparker.userId = env.USER_ID
                    pipelineConfig.netsparker.token = env.TOKEN
                }
            }
        }

        stage('Scan') {
            steps{
                echo '*********************** SECURITY SCAN ASSETS ***********************'

                println pipelineConfig.netsparker
                netsparkerSecurityScan(pipelineConfig.netsparker)
            }
        }
    }
    
    post {
         always {
             echo '******* ABOUT TO QUIT.....GOOD BYE ***********************'
         }
         success {
             echo '******* SECURITY SCAN SUBMITTED SUCCESSFULLY.... SCAN RESULTS WILL LAND TO YOUR EMAIL ADDRESS....***********************'
         }
         unstable {
             echo '******* SECURITY SCAN IS ACTING WEIRD AND I DO NOT HAVE MORE INFORMATION ABOUT IT....SEE THE LOGS AND TRY TO FIX ME....***********************'
         }
         failure {
             echo '******* SECURITY SCAN FAILED DUE TO ONE OF SEVERAL REASONS: ***********************'
             echo 'JOB BUILD ARGUMENTS, SECURITY SCAN API IS NOT REACHABLE, SECURITY SCAN REJECT YOUR ARGUMENTS AMONG OTHERS....'
         }
     }
}
