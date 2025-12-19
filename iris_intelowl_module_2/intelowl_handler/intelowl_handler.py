#!/usr/bin/env python3
#
#
#  IRIS intelowl Source Code
#  Copyright (C) 2022 - dfir-iris
#  contact@dfir-iris.org
#  Created by dfir-iris - 2022-10-29
#
#  License Apache Software License 3.0


import traceback
from jinja2 import Template

import iris_interface.IrisInterfaceStatus as InterfaceStatus
from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field

from pyintelowl import IntelOwl, IntelOwlClientException
from time import sleep


class IntelowlHandler(object):
    def __init__(self, mod_config, server_config, logger):
        self.mod_config = mod_config
        self.server_config = server_config
        self.intelowl = self.get_intelowl_instance()
        self.log = logger

    def get_intelowl_instance(self):
        """
        Returns an intelowl API instance depending if the key is premium or not

        :return: IntelOwl Instance
        """
        url = self.mod_config.get('intelowl_url')
        key = self.mod_config.get('intelowl_key')
        should_use_proxy = self.mod_config.get('intelowl_should_use_proxy')
        proxies = {}

        if should_use_proxy is True:
            if self.server_config.get('http_proxy'):
                proxies['https'] = self.server_config.get('HTTPS_PROXY')

            if self.server_config.get('https_proxy'):
                proxies['http'] = self.server_config.get('HTTP_PROXY')

        intelowl = IntelOwl(
            key,
            url,
            certificate=None,
            proxies=proxies
        )

        return intelowl

    def prerender_report(self, intelowl_report, playbook_name=None) -> dict:

        pre_render = dict()
        pre_render["results"] = intelowl_report

        analyzer_reports = intelowl_report.get("analyzer_reports")
        connector_reports = intelowl_report.get("connector_reports")

        if analyzer_reports:
            pre_render["nb_analyzer_reports"] = len(analyzer_reports)

        if connector_reports:
            pre_render["nb_connector_reports"] = len(connector_reports)

        iol_report_id = intelowl_report.get("id")
        if iol_report_id:
            iol_report_link = "/".join((self.mod_config.get("intelowl_url").strip("/"), "jobs", str(iol_report_id)))
        else:
            iol_report_link = ""

        pre_render["external_link"] = iol_report_link
        
        # Add playbook name for display in banner
        if playbook_name:
            pre_render["playbook_name"] = playbook_name
            self.log.info(f"Report for playbook: {playbook_name}")
        else:
            pre_render["playbook_name"] = "Unknown Playbook"
            self.log.warning("No playbook_name provided")

        return pre_render
    
    def _add_playbook_banner(self, rendered_html: str, playbook_name: str) -> str:
        """
        Add a playbook name banner at the top of the rendered HTML report
        
        :param rendered_html: The rendered HTML content
        :param playbook_name: Name of the playbook used
        :return: HTML with playbook banner prepended
        """
        if not playbook_name or playbook_name == "Unknown Playbook":
            return rendered_html
        
        playbook_banner = f'''
<div class="alert alert-info" role="alert" style="margin-bottom: 20px; border-left: 4px solid #0dcaf0;">
    <h5 class="alert-heading mb-2"><i class="fas fa-book"></i> IntelOwl Playbook</h5>
    <p class="mb-0"><strong>{playbook_name}</strong></p>
</div>
'''
        
        return playbook_banner + rendered_html

    def gen_domain_report_from_template(self, html_template, intelowl_report, playbook_name=None) -> InterfaceStatus:
        """
        Generates an HTML report for Domain, displayed as an attribute in the IOC

        :param html_template: A string representing the HTML template
        :param intelowl_report: The JSON report fetched with intelowl API
        :param playbook_name: Name of the playbook used
        :return: InterfaceStatus
        """
        template = Template(html_template)
        pre_render = self.prerender_report(intelowl_report, playbook_name)

        try:
            rendered = template.render(pre_render)
            # Add playbook banner if playbook name is provided
            if playbook_name:
                rendered = self._add_playbook_banner(rendered, playbook_name)

        except Exception:

            self.log.error(traceback.format_exc())
            return InterfaceStatus.I2Error(traceback.format_exc())

        return InterfaceStatus.I2Success(data=rendered)

    def gen_ip_report_from_template(self, html_template, intelowl_report, playbook_name=None) -> InterfaceStatus:
        """
        Generates an HTML report for IP, displayed as an attribute in the IOC

        :param html_template: A string representing the HTML template
        :param intelowl_report: The JSON report fetched with intelowl API
        :param playbook_name: Name of the playbook used
        :return: InterfaceStatus
        """
        template = Template(html_template)
        pre_render = self.prerender_report(intelowl_report, playbook_name)

        try:
            rendered = template.render(pre_render)
            # Add playbook banner if playbook name is provided
            if playbook_name:
                rendered = self._add_playbook_banner(rendered, playbook_name)

        except Exception:

            self.log.error(traceback.format_exc())
            return InterfaceStatus.I2Error(traceback.format_exc())

        return InterfaceStatus.I2Success(data=rendered)

    def gen_url_report_from_template(self, html_template, intelowl_report, playbook_name=None) -> InterfaceStatus:
        """
        Generates an HTML report for URL, displayed as an attribute in the IOC

        :param html_template: A string representing the HTML template
        :param intelowl_report: The JSON report fetched with intelowl API
        :param playbook_name: Name of the playbook used
        :return: InterfaceStatus
        """
        template = Template(html_template)
        pre_render = self.prerender_report(intelowl_report, playbook_name)

        try:
            rendered = template.render(pre_render)
            # Add playbook banner if playbook name is provided
            if playbook_name:
                rendered = self._add_playbook_banner(rendered, playbook_name)

        except Exception:

            self.log.error(traceback.format_exc())
            return InterfaceStatus.I2Error(traceback.format_exc())

        return InterfaceStatus.I2Success(data=rendered)

    def gen_hash_report_from_template(self, html_template, intelowl_report, playbook_name=None) -> InterfaceStatus:
        """
        Generates an HTML report for Hash, displayed as an attribute in the IOC

        :param html_template: A string representing the HTML template
        :param intelowl_report: The JSON report fetched with intelowl API
        :param playbook_name: Name of the playbook used
        :return: InterfaceStatus
        """
        template = Template(html_template)
        pre_render = self.prerender_report(intelowl_report, playbook_name)

        try:
            rendered = template.render(pre_render)
            # Add playbook banner if playbook name is provided
            if playbook_name:
                rendered = self._add_playbook_banner(rendered, playbook_name)

        except Exception:

            self.log.error(traceback.format_exc())
            return InterfaceStatus.I2Error(traceback.format_exc())

        return InterfaceStatus.I2Success(data=rendered)

    def gen_generic_report_from_template(self, html_template, intelowl_report, playbook_name=None) -> InterfaceStatus:
        """
        Generates an HTML report for Generic ioc, displayed as an attribute in the IOC

        :param html_template: A string representing the HTML template
        :param intelowl_report: The JSON report fetched with intelowl API
        :param playbook_name: Name of the playbook used
        :return: InterfaceStatus
        """
        template = Template(html_template)
        pre_render = self.prerender_report(intelowl_report, playbook_name)

        try:
            rendered = template.render(pre_render)
            # Add playbook banner if playbook name is provided
            if playbook_name:
                rendered = self._add_playbook_banner(rendered, playbook_name)

        except Exception:

            self.log.error(traceback.format_exc())
            return InterfaceStatus.I2Error(traceback.format_exc())

        return InterfaceStatus.I2Success(data=rendered)

    def _all_analyzers_completed(self, job_result):
        """
        Check if all analyzers in the job have completed (SUCCESS or FAILED status)
        
        :param job_result: The job result from IntelOwl API
        :return: bool - True if all analyzers are completed, False otherwise
        """
        analyzer_reports = job_result.get("analyzer_reports", [])
        
        # If no analyzer reports yet, not completed
        if not analyzer_reports:
            return False
        
        completed_statuses = {"SUCCESS", "FAILED"}
        
        for analyzer in analyzer_reports:
            analyzer_status = analyzer.get("status", "").upper()
            if analyzer_status not in completed_statuses:
                self.log.debug(f"Analyzer '{analyzer.get('name', 'unknown')}' still in status: {analyzer_status}")
                return False
        
        return True

    def get_job_result(self, job_id):
        """
        Periodically fetches job status until it's finished to get the results.
        Waits for both job status AND all analyzer statuses to be completed.

        :param job_id: Union[int, str], The job ID to query
        :return:
        """
        try:
            max_job_time = self.mod_config.get("intelowl_maxtime") * 60
        except Exception:
            self.log.error(traceback.format_exc())
            return InterfaceStatus.I2Error(traceback.format_exc())

        wait_interval = 2

        job_result = self.intelowl.get_job_by_id(job_id)
        status = job_result["status"]

        spent_time = 0
        # Wait for job status to not be pending/running
        while (status == "pending" or status == "running") and spent_time <= max_job_time:
            sleep(wait_interval)
            spent_time += wait_interval
            job_result = self.intelowl.get_job_by_id(job_id)
            status = job_result["status"]
            self.log.debug(f"Job {job_id} status: {status}, spent time: {spent_time}s")

        # Additionally wait for all analyzers to complete (SUCCESS or FAILED)
        while not self._all_analyzers_completed(job_result) and spent_time <= max_job_time:
            self.log.info(f"Job {job_id} completed but waiting for all analyzers to finish...")
            sleep(wait_interval)
            spent_time += wait_interval
            job_result = self.intelowl.get_job_by_id(job_id)

        if spent_time > max_job_time:
            self.log.warning(f"Job {job_id} timed out after {spent_time}s. Some analyzers may not have completed.")
        else:
            self.log.info(f"Job {job_id} and all analyzers completed successfully.")

        return job_result

    def _ioc_has_intelowl_report(self, ioc) -> bool:
        """
        Check if IOC already has IntelOwl report attribute
        
        :param ioc: IOC instance
        :return: True if report exists, False otherwise
        """
        try:
            # Check if IOC has custom_attributes
            if hasattr(ioc, 'custom_attributes') and ioc.custom_attributes:
                # Parse custom attributes to check for IntelOwl Report tab
                import json
                if isinstance(ioc.custom_attributes, str):
                    attrs = json.loads(ioc.custom_attributes)
                else:
                    attrs = ioc.custom_attributes
                
                # Check if IntelOwl Report tab exists
                if 'IntelOwl Report' in attrs:
                    self.log.info(f"IOC {ioc.ioc_value} already has IntelOwl report. Skipping.")
                    return True
        except Exception as e:
            self.log.debug(f"Error checking IOC attributes: {e}")
        
        return False

    def handle_domain(self, ioc):
        """
        Handles an IOC of type domain and adds IntelOwl insights

        :param ioc: IOC instance
        :return: IIStatus
        """
        
        # Skip if IOC already has IntelOwl report
        if self._ioc_has_intelowl_report(ioc):
            return InterfaceStatus.I2Success()

        self.log.info(f'Getting domain report for {ioc.ioc_value}')

        domain = ioc.ioc_value
        playbook_name = self.mod_config.get("intelowl_playbook_name")
        try:
            query_result = self.intelowl.send_observable_analysis_playbook_request(observable_name=domain,
                                                                                   playbook_requested=playbook_name,
                                                                                   tags_labels=["iris"],
                                                                                   observable_classification="domain")
        except IntelOwlClientException as e:
            self.log.error(e)
            return InterfaceStatus.I2Error(e)

        job_id = query_result.get("job_id")

        try:
            job_result = self.get_job_result(job_id)
        except IntelOwlClientException as e:
            self.log.error(e)
            return InterfaceStatus.I2Error(e)

        if self.mod_config.get('intelowl_report_as_attribute') is True:
            self.log.info('Adding new attribute IntelOwl Domain Report to IOC')

            report = job_result

            status = self.gen_domain_report_from_template(self.mod_config.get('intelowl_domain_report_template'),
                                                          report, playbook_name)

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='IntelOwl Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success()

    def handle_ip(self, ioc):
        """
        Handles an IOC of type ip and adds IntelOwl insights

        :param ioc: IOC instance
        :return: IIStatus
        """
        
        # Skip if IOC already has IntelOwl report
        if self._ioc_has_intelowl_report(ioc):
            return InterfaceStatus.I2Success()

        self.log.info(f'Getting IP report for {ioc.ioc_value}')

        ip = ioc.ioc_value
        playbook_name = self.mod_config.get("intelowl_playbook_name")
        try:
            query_result = self.intelowl.send_observable_analysis_playbook_request(observable_name=ip,
                                                                                   playbook_requested=playbook_name,
                                                                                   tags_labels=["iris"],
                                                                                   observable_classification="ip")
        except IntelOwlClientException as e:
            self.log.error(e)
            return InterfaceStatus.I2Error(e)

        job_id = query_result.get("job_id")

        try:
            job_result = self.get_job_result(job_id)
        except IntelOwlClientException as e:
            self.log.error(e)
            return InterfaceStatus.I2Error(e)

        if self.mod_config.get('intelowl_report_as_attribute') is True:
            self.log.info('Adding new attribute IntelOwl IP Report to IOC')

            report = job_result

            status = self.gen_ip_report_from_template(self.mod_config.get('intelowl_ip_report_template'), report, playbook_name)

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='IntelOwl Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success()

    def handle_url(self, ioc):
        """
        Handles an IOC of type URL and adds IntelOwl insights

        :param ioc: IOC instance
        :return: IIStatus
        """
        
        # Skip if IOC already has IntelOwl report
        if self._ioc_has_intelowl_report(ioc):
            return InterfaceStatus.I2Success()

        self.log.info(f'Getting URL report for {ioc.ioc_value}')

        url = ioc.ioc_value
        playbook_name = self.mod_config.get("intelowl_playbook_name")
        try:
            query_result = self.intelowl.send_observable_analysis_playbook_request(observable_name=url,
                                                                                   playbook_requested=playbook_name,
                                                                                   tags_labels=["iris"],
                                                                                   observable_classification="url")
        except IntelOwlClientException as e:
            self.log.error(e)
            return InterfaceStatus.I2Error(e)

        job_id = query_result.get("job_id")

        try:
            job_result = self.get_job_result(job_id)
        except IntelOwlClientException as e:
            self.log.error(e)
            return InterfaceStatus.I2Error(e)

        if self.mod_config.get('intelowl_report_as_attribute') is True:
            self.log.info('Adding new attribute IntelOwl URL Report to IOC')

            report = job_result

            status = self.gen_url_report_from_template(self.mod_config.get('intelowl_url_report_template'), report, playbook_name)

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='IntelOwl Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success()

    def handle_hash(self, ioc):
        """
        Handles an IOC of type hash and adds IntelOwl insights

        :param ioc: IOC instance
        :return: IIStatus
        """
        
        # Skip if IOC already has IntelOwl report
        if self._ioc_has_intelowl_report(ioc):
            return InterfaceStatus.I2Success()

        self.log.info(f'Getting hash report for {ioc.ioc_value}')

        hash = ioc.ioc_value
        playbook_name = self.mod_config.get("intelowl_playbook_name")
        try:
            query_result = self.intelowl.send_observable_analysis_playbook_request(observable_name=hash,
                                                                                   playbook_requested=playbook_name,
                                                                                   tags_labels=["iris"],
                                                                                   observable_classification="hash")
        except IntelOwlClientException as e:
            self.log.error(e)
            return InterfaceStatus.I2Error(e)

        job_id = query_result.get("job_id")

        try:
            job_result = self.get_job_result(job_id)
        except IntelOwlClientException as e:
            self.log.error(e)
            return InterfaceStatus.I2Error(e)

        if self.mod_config.get('intelowl_report_as_attribute') is True:
            self.log.info('Adding new attribute IntelOwl hash Report to IOC')

            report = job_result

            status = self.gen_hash_report_from_template(self.mod_config.get('intelowl_hash_report_template'), report, playbook_name)

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='IntelOwl Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success()

    def handle_generic(self, ioc):
        """
        Handles an IOC of type generic and adds IntelOwl insights

        :param ioc: IOC instance
        :return: IIStatus
        """
        
        # Skip if IOC already has IntelOwl report
        if self._ioc_has_intelowl_report(ioc):
            return InterfaceStatus.I2Success()

        self.log.info(f'Getting generic report for {ioc.ioc_value}')

        generic = ioc.ioc_value
        playbook_name = self.mod_config.get("intelowl_playbook_name")
        try:
            query_result = self.intelowl.send_observable_analysis_playbook_request(observable_name=generic,
                                                                                   playbook_requested=playbook_name,
                                                                                   tags_labels=["iris"],
                                                                                   observable_classification="generic")
        except IntelOwlClientException as e:
            self.log.error(e)
            return InterfaceStatus.I2Error(e)

        job_id = query_result.get("job_id")

        try:
            job_result = self.get_job_result(job_id)
        except IntelOwlClientException as e:
            self.log.error(e)
            return InterfaceStatus.I2Error(e)

        if self.mod_config.get('intelowl_report_as_attribute') is True:
            self.log.info('Adding new attribute IntelOwl generic Report to IOC')

            report = job_result

            status = self.gen_generic_report_from_template(self.mod_config.get('intelowl_generic_report_template'),
                                                           report, playbook_name)

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='IntelOwl Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success()
