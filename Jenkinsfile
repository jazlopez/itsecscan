#!groovy
/**
 * Improvements:
 * pipelineconfig.netsparker convert to only netsparker_args
 */
@Library('depl@v1') _ // Library reference, notice the underscore
import com.thermofisher.utils.DECPUtils

def scanPayload = [
        TargetUri: '',
        ExcludedLinks: [
                [RegexPattern: '(log|sign)\\-?(out|off)']
        ],
        ImportedLinks: [],
        ImportedFiles: [],
        IsMaxScanDurationEnabled: false,
        MaxDynamicSignatures: 60,
        MaxScanDuration: 48,
        FormAuthenticationSettingModel: [
                LoginFormUrl: '',
                Personas: [
                        [IsActive: true, Password: '', UserName: '']
                ],
                DefaultPersonaValidation: true,
                DetectBearerToken: true,
                DisableLogoutDetection: true,
                IsEnabled: true,
                OverrideTargetUrl: false,
                PersonasValidation: true
        ],
        CrawlAndAttack: true,
        EnableHeuristicChecksInCustomUrlRewrite: true,
        DisallowedHttpMethods: [],
        ExcludeLinks: true,
        FindAndFollowNewLinks: true,
        PolicyId: '010c4f1a1f9645f80053a89b0232a610',
        Scope: 'EnteredPathAndBelow',
        SubPathMaxDynamicSignatures: 30,
        TimeWindow: null,
        UrlRewriteAnalyzableExtensions: 'htm,html',
        UrlRewriteBlocksSeparators: '/$.,;|:',
        UrlRewriteMode: 'Heuristic'
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

                    // validations
                    params.URI_PATH = !params.URI_PATH ? "/" : params.URI_PATH
                    params.URI_PATH = params.URI_PATH.trim()
                    params.FORM_LOGIN_USERNAME = params.FORM_LOGIN_USERNAME.trim()

                    // netspark credentials
                    pipelineConfig.netsparker.userId = env.USER_ID
                    pipelineConfig.netsparker.token = env.TOKEN
                    pipelineConfig.netsparker.scanQuery.TargetUri = params.TARGET_URI + params.URI_PATH

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
