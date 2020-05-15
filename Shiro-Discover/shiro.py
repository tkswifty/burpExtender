# /usr/bin/env python
# _*_ coding:utf-8 _*_
__author__ = 'tkswifty'

from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService
import sys
import time
import os
import re
import requests
import random


class BurpExtender(IBurpExtender, IHttpListener):

    def __init__(self):
        self.payload = ['rememberMe']
        

    def registerExtenderCallbacks(self, callbacks):
        print("[+] #####################################")
        print("[+]     Shiro Discovery")
        print("[+]     Author: tkswifty")
        print("[+] #####################################\r\n\r\n")
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('Shiro Discovery')
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_REPEATER:
            # 监听Response
            if not messageIsRequest:

                '''请求数据'''
                # 获取请求包的数据
                resquest = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeRequest(resquest)
                request_header = analyzedRequest.getHeaders()
                request_bodys = resquest[analyzedRequest.getBodyOffset():].tostring()
                request_host, request_Path = self.get_request_host(request_header)
                request_contentType = analyzedRequest.getContentType()


                # 获取服务端的信息，主机地址，端口，协议
                httpService = messageInfo.getHttpService()
                port = httpService.getPort()
                host = httpService.getHost()
                protocol = httpService.getProtocol()

                #修改cookie检测shiro
                self.sendPayload(request_header, host, port, protocol, request_bodys,messageInfo)


    # 发起请求并进行Shiro检测
    def sendPayload(self, request_header, host, port, protocol, request_bodys,messageInfo):
            for i in xrange(0,len(request_header)):
                    if request_header[i].startswith("Cookie:"):
                        for shiroHeader in self.payload:
                            request_header[i] = request_header[i]+";"+shiroHeader+"=tkswifty;"
                            newRequest = self._helpers.buildHttpMessage(request_header,self._helpers.stringToBytes(request_bodys))
                            if 's' in protocol:
                                ishttps = True
                            else:
                                ishttps = False
                            expression = r'.*(443).*'
                            if re.match(expression, str(port)):
                                ishttps = True
                            rep = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

                            #新的请求响应包
                            analyzedResponse = self._helpers.analyzeResponse(rep)
                            rep_headers = analyzedResponse.getHeaders()
                            expression = r'.*(deleteMe).*'
                            for rpheader in rep_headers:
                                if rpheader.startswith("Set-Cookie:") and re.match(expression, rpheader):
                                    response_is_shiro = True
                                    messageInfo.setHighlight('orange')
                                    print "[+] Find Shiro application"
                                    print "\t[-] host:" + str(host)
                                    print "\t[-] port:" + str(port)

    # 获取请求的url
    def get_request_host(self, reqHeaders):
        uri = reqHeaders[0].split(' ')[1]
        host = reqHeaders[1].split(' ')[1]
        return host, uri

    # 获取请求的一些信息：请求头，请求内容，请求方法，请求参数
    def get_request_info(self, request):
        analyzedIRequestInfo = self._helpers.analyzeRequest(request)
        reqHeaders = analyzedIRequestInfo.getHeaders()
        reqBodys = request[analyzedIRequestInfo.getBodyOffset():].tostring()
        reqMethod = analyzedIRequestInfo.getMethod()
        reqParameters = analyzedIRequestInfo.getParameters()
        reqHost, reqPath = self.get_request_host(reqHeaders)
        reqContentType = analyzedIRequestInfo.getContentType()
        print(reqHost, reqPath)
        return analyzedIRequestInfo, reqHeaders, reqBodys, reqMethod, reqParameters, reqHost, reqContentType

    # 获取响应的一些信息：响应头，响应内容，响应状态码
    def get_response_info(self, response):
        analyzedIResponseInfo = self._helpers.analyzeRequest(response)
        resHeaders = analyzedIResponseInfo.getHeaders()
        resBodys = response[analyzedIResponseInfo.getBodyOffset():].tostring()
        # getStatusCode获取响应中包含的HTTP状态代码。返回：响应中包含的HTTP状态代码。
        # resStatusCode = analyzedIResponseInfo.getStatusCode()
        return resHeaders, resBodys

    # 获取请求的参数名、参数值、参数类型（get、post、cookie->用来构造参数时使用）
    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def doPassiveScan(self, baseRequestResponse):
        self.issues = []
        self.start_run(baseRequestResponse)
        return self.issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        '''
        相同的数据包，只报告一份报告
        :param existingIssue:
        :param newIssue:
        :return:
        '''

        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1

        return 0
