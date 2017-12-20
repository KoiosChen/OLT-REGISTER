import requests


def customerInfoQueryAction(query_info, loginName):
    """

    :param query_info: 用户编号或者用户登陆名
    :param loginName: 工单平台编号
    :return: 工单平台返回的格式化字符串, 例如：
    {"accountId": null, "accountName": "xz101388", "accountPhone": null, "accountRealName": null, "accountStatus": null,
     "customerListInfo": {"customerList": [
         {"accountId": 21048702, "accounttype": "50M两年交1299元加1元换购机顶盒（烽火）", "aptNo": "盛龙路429弄30号", "bandwidth": "50M",
          "buildingId": "16931", "buildingNo": "1", "centerId": 1054, "centerName": "未运营区域",
          "certificateNo": "340881198508255319", "certificateTypeId": 1, "certificateTypeName": "身份证", "commName": null,
          "communityId": 5011, "communityName": "H-沪亭南路", "currentState": "2", "currentStateName": "开通",
          "dateOfEnd": "2018-08-10", "dateOfKaitong": "2016-08-11", "dateOfOpen": "2016-08-11",
          "dateOfPayEnd": "2018-08-10", "isHasPic": 0, "loginName": "xz101388", "mobilePhone": "13611913878",
          "password": "13611913878", "phone": null, "remark": null, "userClass": 1, "userName": "吴福候"}],
                          "oper": {"operContent": "操作成功", "operInfo": "oper_suc"}, "totalNum": "1"},
     "loginUserId": "admin", "pageNum": "0", "pageSize": "10"}
    """
    i = 0
    for _type in ['accountId', 'accountName']:
        fb = url_template(
            'http://1.14.191.22/NGOSS/androidCustomerInfoQueryAction.action?{type}={query_info}&loginUserId={loginName}&pageSize=1&pageNum=0')
        r = fb(type=_type, query_info=query_info, loginName=loginName)
        result = r.json()
        if not result['customerListInfo']['customerList'] and i == 0:
            i += 1
            continue
        else:
            return r.json()


def url_template(template):
    def opener(**kwargs):
        return requests.get(template.format_map(kwargs))

    return opener
