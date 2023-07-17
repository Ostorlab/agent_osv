"""Unittests for CVE service api."""
import re

import requests_mock as rq_mock
from pytest_mock import plugin

from agent import cve_service_api


def testGetCveData_withResponse_returnRiskRating(
    mocker: plugin.MockerFixture,
    requests_mock: rq_mock.mocker.Mocker,
) -> None:
    cve_data_json = """
    {
   "resultsPerPage":1,
   "startIndex":0,
   "totalResults":1,
   "result":{
      "CVE_data_type":"CVE",
      "CVE_data_format":"MITRE",
      "CVE_data_version":"4.0",
      "CVE_data_timestamp":"2023-07-17T10:59Z",
      "CVE_Items":[
         {
            "cve":{
               "data_type":"CVE",
               "data_format":"MITRE",
               "data_version":"4.0",
               "CVE_data_meta":{
                  "ID":"CVE-2021-44228",
                  "ASSIGNER":"security@apache.org"
               },
               "problemtype":{
                  "problemtype_data":[
                     {
                        "description":[
                           {
                              "lang":"en",
                              "value":"CWE-20"
                           },
                           {
                              "lang":"en",
                              "value":"CWE-400"
                           },
                           {
                              "lang":"en",
                              "value":"CWE-502"
                           }
                        ]
                     }
                  ]
               },
               "references":{
                  "reference_data":[]
               },
               "description":{
                  "description_data":[
                     {
                        "lang":"en",
                        "value":""
                     }
                  ]
               }
            },
            "configurations":{
               "CVE_data_version":"4.0",
               "nodes":[
                  {},
                  {
                     "operator":"AND",
                     "children":[],
                     "cpe_match":[]
                  },
                  {
                     "operator":"OR",
                     "children":[],
                     "cpe_match":[]
                  },
                  {
                     "operator":"OR",
                     "children":[
                        
                     ],
                     "cpe_match":[
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:intel:audio_development_kit:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:intel:system_debugger:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:intel:secure_device_onboard:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:intel:oneapi_sample_browser:-:*:*:*:*:eclipse:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:intel:sensor_solution_firmware_development_kit:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:intel:computer_vision_annotation_tool:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:intel:genomics_kernel_library:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:intel:system_studio:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:intel:data_center_manager:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"5.1",
                           "cpe_name":[
                              
                           ]
                        }
                     ]
                  },
                  {
                     "operator":"OR",
                     "children":[
                        
                     ],
                     "cpe_match":[
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        }
                     ]
                  },
                  {
                     "operator":"OR",
                     "children":[
                        
                     ],
                     "cpe_match":[
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        }
                     ]
                  },
                  {
                     "operator":"OR",
                     "children":[
                        
                     ],
                     "cpe_match":[
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:sonicwall:email_security:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"10.0.12",
                           "cpe_name":[
                              
                           ]
                        }
                     ]
                  },
                  {
                     "operator":"OR",
                     "children":[
                        
                     ],
                     "cpe_match":[
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:netapp:oncommand_insight:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:netapp:cloud_insights:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vmware_vsphere:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:linux:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:windows:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:netapp:cloud_manager:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:netapp:cloud_secure_agent:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:netapp:ontap_tools:-:*:*:*:*:vmware_vsphere:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:netapp:snapcenter:-:*:*:*:*:vmware_vsphere:*:*",
                           "cpe_name":[
                              
                           ]
                        }
                     ]
                  },
                  {
                     "operator":"OR",
                     "children":[
                        
                     ],
                     "cpe_match":[
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager_im_and_presence_service:11.5\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_customer_voice_portal:11.6:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"3.0",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:packaged_contact_center_enterprise:11.6\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:3.0:maintenance_release1:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:3.0:-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:identity_services_engine:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.4.0",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:data_center_network_manager:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"11.3\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:3.0:maintenance_release2:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:3.0:maintenance_release3:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:4.0:-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:4.0:maintenance_release1:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:4.0:maintenance_release2:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:4.0:maintenance_release3:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_express:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"12.5\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:data_center_network_manager:11.3\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:3.0:maintenance_release3:-:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:3.0:maintenance_release3_service_pack_2:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:3.0:maintenance_release3_service_pack_3:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:3.0:maintenance_release4:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:3.0:maintenance_release3_security_patch4:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:identity_services_engine:2.4.0:-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:finesse:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"12.6\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:finesse:12.6\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:nexus_dashboard:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.1.2",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_services_orchestrator:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"5.6",
                           "versionEndExcluding":"5.6.3.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_services_orchestrator:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"5.5",
                           "versionEndExcluding":"5.5.4.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_services_orchestrator:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"5.3.5.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:iot_operations_dashboard:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:intersight_virtual_appliance:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"1.0.9-361",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:evolved_programmable_network_manager:*:*:*:*:*:*:*:*",
                           "versionEndIncluding":"4.1.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_services_orchestrator:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"5.4",
                           "versionEndExcluding":"5.4.5.2",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:dna_spaces\\:_connector:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.5",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cyber_vision_sensor_management_extension:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"4.0.3",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_zero_touch_provisioning:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.0.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_zero_touch_provisioning:3.0.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_platform_infrastructure:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"4.0.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_platform_infrastructure:4.1.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_optimization_engine:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.0.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_optimization_engine:3.0.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_network_controller:3.0.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_network_controller:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.0.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_data_gateway:3.0.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_data_gateway:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.0.2",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:common_services_platform_collector:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"2.10.0",
                           "versionEndExcluding":"2.10.0.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:common_services_platform_collector:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.9.1.3",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cloudcenter:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"4.10.0.16",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cloudcenter_workload_manager:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"5.5.2",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cloudcenter_suite_admin:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"5.3.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cloudcenter_cost_optimizer:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"5.5.2",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:business_process_automation:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"3.2.000.000",
                           "versionEndExcluding":"3.2.000.009",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:business_process_automation:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"3.1.000.000",
                           "versionEndExcluding":"3.1.000.044",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:business_process_automation:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"3.0.000.115",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:automated_subsea_tuning:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.1.0",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:nexus_insights:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"6.0.2",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:advanced_malware_protection_virtual_private_cloud_appliance:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"3.5.4",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:customer_experience_cloud_agent:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"1.12.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:3.0:maintenance_release3_security_patch5:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:workload_optimization_manager:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"3.2.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.0\\(1p\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_director:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"6.8.2.0",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:sd-wan_vmanage:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"20.3.4.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:optical_network_controller:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"1.1.0",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:fog_director:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:dna_center:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"2.2.3.0",
                           "versionEndExcluding":"2.2.3.4",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:sd-wan_vmanage:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"20.4",
                           "versionEndExcluding":"20.4.2.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:integrated_management_controller_supervisor:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.3.2.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:wan_automation_engine:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"7.3.0.2",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:virtualized_infrastructure_manager:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"3.4.0",
                           "versionEndExcluding":"3.4.4",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:sd-wan_vmanage:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"20.5",
                           "versionEndExcluding":"20.5.1.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_assurance_engine:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"6.0.2",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:virtualized_infrastructure_manager:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"3.2.0",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:dna_center:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.1.2.8",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:sd-wan_vmanage:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"20.6",
                           "versionEndExcluding":"20.6.2.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:virtual_topology_system:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2.6.7",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:dna_center:*:*:*:*:*:*:*:*",
                           "versionStartIncluding":"2.2.2.0",
                           "versionEndExcluding":"2.2.2.8",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:smart_phy:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"3.2.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:prime_service_catalog:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"12.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_mobile_experiences:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:video_surveillance_operations_manager:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"7.14.4",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unity_connection:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"11.5\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:virtualized_voice_browser:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"12.5\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:o:cisco:unified_workforce_optimization:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"11.5\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:o:cisco:unified_sip_proxy:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"10.2.1v2",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:o:cisco:unified_intelligence_center:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"12.6\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_customer_voice_portal:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"11.6",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_customer_voice_portal:12.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_customer_voice_portal:12.5:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_enterprise:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"11.6\\(2\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_enterprise:11.6\\(2\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager_im_and_presence_service:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"11.5\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager:*:*:*:*:session_management:*:*:*",
                           "versionEndExcluding":"11.5\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager:*:*:*:*:-:*:*:*",
                           "versionEndExcluding":"11.5\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager:11.5\\(1\\)su3:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager:11.5\\(1\\):*:*:*:session_management:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager:11.5\\(1\\):*:*:*:-:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:paging_server:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"14.4.1",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager:11.5\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:packaged_contact_center_enterprise:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"11.6",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:enterprise_chat_and_email:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"12.0\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:emergency_responder:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"11.5\\(4\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:contact_center_management_portal:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"12.5\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:contact_center_domain_manager:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"12.5\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cloud_connect:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"12.6\\(1\\)",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:broadworks:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"2021.11_1.162",
                           "cpe_name":[
                              
                           ]
                        }
                     ]
                  },
                  {
                     "operator":"AND",
                     "children":[
                        {
                           "operator":"OR",
                           "children":[
                              
                           ],
                           "cpe_match":[
                              {
                                 "vulnerable":true,
                                 "cpe23Uri":"cpe:2.3:o:cisco:fxos:6.2.3:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":true,
                                 "cpe23Uri":"cpe:2.3:o:cisco:fxos:6.3.0:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":true,
                                 "cpe23Uri":"cpe:2.3:o:cisco:fxos:6.4.0:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":true,
                                 "cpe23Uri":"cpe:2.3:o:cisco:fxos:6.5.0:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":true,
                                 "cpe23Uri":"cpe:2.3:o:cisco:fxos:6.6.0:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":true,
                                 "cpe23Uri":"cpe:2.3:o:cisco:fxos:6.7.0:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":true,
                                 "cpe23Uri":"cpe:2.3:o:cisco:fxos:7.0.0:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":true,
                                 "cpe23Uri":"cpe:2.3:o:cisco:fxos:7.1.0:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              }
                           ]
                        },
                        {
                           "operator":"OR",
                           "children":[
                              
                           ],
                           "cpe_match":[
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_1010:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_1120:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_1140:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_1150:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_2110:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_2120:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_2130:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_2140:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_4110:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_4112:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_4115:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_4120:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_4125:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_4140:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_4145:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_4150:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              },
                              {
                                 "vulnerable":false,
                                 "cpe23Uri":"cpe:2.3:h:cisco:firepower_9300:-:*:*:*:*:*:*:*",
                                 "cpe_name":[
                                    
                                 ]
                              }
                           ]
                        }
                     ],
                     "cpe_match":[
                        
                     ]
                  },
                  {
                     "operator":"OR",
                     "children":[
                        
                     ],
                     "cpe_match":[
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:prime_service_catalog:12.1:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:firepower_threat_defense:6.2.3:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:3.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:firepower_threat_defense:6.4.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:firepower_threat_defense:6.3.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:webex_meetings_server:4.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unity_connection:11.5:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:firepower_threat_defense:6.5.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:firepower_threat_defense:6.6.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:sd-wan_vmanage:20.3:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:sd-wan_vmanage:20.6:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:sd-wan_vmanage:20.5:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_enterprise:11.6\\(2\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cyber_vision_sensor_management_extension:4.0.2:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:dna_spaces_connector:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_sip_proxy:010.002\\(001\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_sip_proxy:010.002\\(000\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_sip_proxy:010.000\\(001\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_sip_proxy:010.000\\(000\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_intelligence_center:12.6\\(2\\):-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_intelligence_center:12.6\\(1\\):es02:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_intelligence_center:12.6\\(1\\):es01:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_intelligence_center:12.6\\(1\\):-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_customer_voice_portal:12.6\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_customer_voice_portal:12.5\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_customer_voice_portal:12.0\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_customer_voice_portal:11.6\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_express:12.5\\(1\\):su1:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_express:12.5\\(1\\):-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager_im_\\&_presence_service:11.5\\(1.22900.6\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager_im_\\&_presence_service:11.5\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager:11.5\\(1.22900.28\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager:11.5\\(1.21900.40\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager:11.5\\(1.18900.97\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager:11.5\\(1.18119.2\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_communications_manager:11.5\\(1.17900.52\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:paging_server:9.1\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:paging_server:9.0\\(2\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:paging_server:9.0\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:paging_server:8.5\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:paging_server:8.4\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:paging_server:8.3\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:paging_server:14.0\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:paging_server:12.5\\(2\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_enterprise:12.6\\(2\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_enterprise:12.6\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_enterprise:12.5\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_enterprise:12.0\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:finesse:12.6\\(1\\):es03:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:finesse:12.6\\(1\\):es02:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:finesse:12.6\\(1\\):es01:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:finesse:12.6\\(1\\):-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:finesse:12.5\\(1\\):su2:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:finesse:12.5\\(1\\):su1:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:enterprise_chat_and_email:12.6\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:enterprise_chat_and_email:12.5\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:enterprise_chat_and_email:12.0\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:emergency_responder:11.5\\(4.66000.14\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:emergency_responder:11.5\\(4.65000.14\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:emergency_responder:11.5:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_management_portal:12.6\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_express:12.6\\(2\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_contact_center_express:12.6\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:broadworks:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_computing_system:006.008\\(001.000\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central_software:2.0\\(1l\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central_software:2.0\\(1k\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central_software:2.0\\(1h\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central_software:2.0\\(1g\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central_software:2.0\\(1f\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central_software:2.0\\(1e\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central_software:2.0\\(1d\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central_software:2.0\\(1c\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central_software:2.0\\(1b\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central_software:2.0\\(1a\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:ucs_central_software:2.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:integrated_management_controller_supervisor:2.3.2.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:integrated_management_controller_supervisor:002.003\\(002.000\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:sd-wan_vmanage:20.6.1:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:sd-wan_vmanage:20.8:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:sd-wan_vmanage:20.7:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:sd-wan_vmanage:20.4:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:optical_network_controller:1.1:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_assurance_engine:6.0\\(2.1912\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:dna_center:2.2.2.8:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:wan_automation_engine:7.6:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:wan_automation_engine:7.5:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:wan_automation_engine:7.4:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:wan_automation_engine:7.3:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:wan_automation_engine:7.2.3:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:wan_automation_engine:7.2.2:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:wan_automation_engine:7.2.1:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:wan_automation_engine:7.1.3:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:virtual_topology_system:2.6.6:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:smart_phy:3.2.1:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:smart_phy:3.1.5:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:smart_phy:3.1.4:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:smart_phy:3.1.3:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:smart_phy:3.1.2:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:smart_phy:21.3:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_services_orchestrator:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:intersight_virtual_appliance:1.0.9-343:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:evolved_programmable_network_manager:5.1:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:evolved_programmable_network_manager:5.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:evolved_programmable_network_manager:4.1:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:evolved_programmable_network_manager:4.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:evolved_programmable_network_manager:3.1:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:evolved_programmable_network_manager:3.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_dashboard_fabric_controller:11.5\\(3\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_dashboard_fabric_controller:11.5\\(2\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_dashboard_fabric_controller:11.5\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_dashboard_fabric_controller:11.4\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_dashboard_fabric_controller:11.3\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_dashboard_fabric_controller:11.2\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_dashboard_fabric_controller:11.1\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_dashboard_fabric_controller:11.0\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:video_surveillance_manager:7.14\\(4.018\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:video_surveillance_manager:7.14\\(3.025\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:video_surveillance_manager:7.14\\(2.26\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:video_surveillance_manager:7.14\\(1.26\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unified_workforce_optimization:11.5\\(1\\):sr7:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:unity_connection:11.5\\(1.10000.6\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cloudcenter_suite:5.3\\(0\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cloudcenter_suite:5.5\\(0\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cloudcenter_suite:5.4\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:automated_subsea_tuning:02.01.00:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:identity_services_engine:003.002\\(000.116\\):-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:identity_services_engine:003.001\\(000.518\\):-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:identity_services_engine:003.000\\(000.458\\):-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:identity_services_engine:002.007\\(000.356\\):-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:identity_services_engine:002.006\\(000.156\\):-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:identity_services_engine:002.004\\(000.914\\):-:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:firepower_threat_defense:7.1.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:firepower_threat_defense:7.0.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:firepower_threat_defense:6.7.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:network_insights_for_data_center:6.0\\(2.1914\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cx_cloud_agent:001.012:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:mobility_services_engine:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cloudcenter_suite:5.5\\(1\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cloudcenter_suite:4.10\\(0.15\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:dna_spaces:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:cyber_vision:4.0.2:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:7.3:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:008.000.000.000.004:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:008.000.000:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:007.003.003:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:007.003.001.001:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:007.003.000:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:007.002.000:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:007.001.000:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:007.000.001:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:006.005.000.000:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:006.005.000.:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:connected_analytics_for_network_deployment:006.004.000.003:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_network_automation:4.1.1:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_network_automation:4.1.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_network_automation:-:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_network_automation:3.0.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:crosswork_network_automation:2.0.0:*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:common_services_platform_collector:002.010\\(000.000\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:common_services_platform_collector:002.009\\(001.002\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:common_services_platform_collector:002.009\\(001.001\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:common_services_platform_collector:002.009\\(001.000\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:common_services_platform_collector:002.009\\(000.002\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:common_services_platform_collector:002.009\\(000.001\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:cisco:common_services_platform_collector:002.009\\(000.000\\):*:*:*:*:*:*:*",
                           "cpe_name":[
                              
                           ]
                        }
                     ]
                  },
                  {
                     "operator":"OR",
                     "children":[
                        
                     ],
                     "cpe_match":[
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:snowsoftware:vm_access_proxy:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"3.6",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:snowsoftware:snow_commander:*:*:*:*:*:*:*:*",
                           "versionEndExcluding":"8.10.0",
                           "cpe_name":[
                              
                           ]
                        }
                     ]
                  },
                  {
                     "operator":"OR",
                     "children":[
                        
                     ],
                     "cpe_match":[
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:bentley:synchro_4d:*:*:*:*:pro:*:*:*",
                           "versionEndExcluding":"6.2.4.2",
                           "cpe_name":[
                              
                           ]
                        },
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:bentley:synchro:*:*:*:*:pro:*:*:*",
                           "versionStartIncluding":"6.1",
                           "versionEndExcluding":"6.4.3.2",
                           "cpe_name":[
                              
                           ]
                        }
                     ]
                  },
                  {
                     "operator":"OR",
                     "children":[
                        
                     ],
                     "cpe_match":[
                        {
                           "vulnerable":true,
                           "cpe23Uri":"cpe:2.3:a:percussion:rhythmyx:*:*:*:*:*:*:*:*",
                           "versionEndIncluding":"7.3.2",
                           "cpe_name":[
                              
                           ]
                        }
                     ]
                  }
               ]
            },
            "impact":{
               "baseMetricV3":{
                  "cvssV3":{
                     "version":"3.1",
                     "vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                     "attackVector":"NETWORK",
                     "attackComplexity":"LOW",
                     "privilegesRequired":"NONE",
                     "userInteraction":"NONE",
                     "scope":"CHANGED",
                     "confidentialityImpact":"HIGH",
                     "integrityImpact":"HIGH",
                     "availabilityImpact":"HIGH",
                     "baseScore":10.0,
                     "baseSeverity":"CRITICAL"
                  },
                  "exploitabilityScore":3.9,
                  "impactScore":6.0
               },
               "baseMetricV2":{
                  "cvssV2":{
                     "version":"2.0",
                     "vectorString":"AV:N/AC:M/Au:N/C:C/I:C/A:C",
                     "accessVector":"NETWORK",
                     "accessComplexity":"MEDIUM",
                     "authentication":"NONE",
                     "confidentialityImpact":"COMPLETE",
                     "integrityImpact":"COMPLETE",
                     "availabilityImpact":"COMPLETE",
                     "baseScore":9.3
                  },
                  "severity":"HIGH",
                  "exploitabilityScore":8.6,
                  "impactScore":10.0,
                  "acInsufInfo":false,
                  "obtainAllPrivilege":false,
                  "obtainUserPrivilege":false,
                  "obtainOtherPrivilege":false,
                  "userInteractionRequired":false
               }
            },
            "publishedDate":"2021-12-10T10:15Z",
            "lastModifiedDate":"2023-04-03T20:15Z"
         }
      ]
   }
}
"""
    requests_mock.get(
        re.compile("https://services.nvd.nist.gov/.*"),
        text=cve_data_json,
    )
    time_mocked = mocker.patch("time.sleep")

    cve_data = cve_service_api.get_cve_data_from_api("CVE-2021-12345")

    assert cve_data.risk == "POTENTIALLY"


def testGetCveData_whenException_returnDefaultValue(
    mocker: plugin.MockerFixture,
    requests_mock: rq_mock.mocker.Mocker,
) -> None:
    requests_mock.get(
        re.compile("https://services.nvd.nist.gov/.*"),
        text="<html><body><h1>503 Service Unavailable</h1>"
        "\nNo server is available to handle this request.\n</body></html>\n",
    )
    time_mocked = mocker.patch("time.sleep")

    cve_data = cve_service_api.get_cve_data_from_api("CVE-2021-1234")

    assert cve_data.risk == "POTENTIALLY"


def testGetCveData_whenRateLimitException_waitFixedBeforeRetry(
    mocker: plugin.MockerFixture,
    requests_mock: rq_mock.mocker.Mocker,
) -> None:
    requests_mock.get(
        re.compile("https://services.nvd.nist.gov/.*"),
        text="<html><body><h1>503 Service Unavailable</h1>"
        "\nNo server is available to handle this request.\n</body></html>\n",
    )
    time_mocked = mocker.patch("time.sleep")

    cve_service_api.get_cve_data_from_api("CVE-2021-1234")

    assert requests_mock.call_count == 10
    assert time_mocked.call_count == 9
    assert time_mocked.call_args_list[0][0][0] == 30.0
