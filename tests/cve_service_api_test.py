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
    mocker.patch("time.sleep")

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
    mocker.patch("time.sleep")

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


def testGetCveData_whenJsonDataIsMissingItems_ReturnDefault(
    requests_mock: rq_mock.mocker.Mocker,
    fake_osv_output_missing_cve: str,
) -> None:
    requests_mock.get(
        re.compile("https://services.nvd.nist.gov/.*"),
        text=fake_osv_output_missing_cve,
    )
    cve = cve_service_api.get_cve_data_from_api("CVE-2021-37713")
    assert requests_mock.call_count == 1
    assert cve.risk == "HIGH"
    assert cve.cvss_v3_vector == "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
