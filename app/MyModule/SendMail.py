import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.header import Header
from email.encoders import _bencode


class sendmail:
    def __init__(self, **kwargs):
        self.HOST = kwargs.setdefault('host', "mail.mbqianbao.com")
        self.SUBJECT = kwargs.setdefault('subject', "report")
        self.TO = kwargs.setdefault('mail_to', "report.tc@mbqianbao.com")
        self.FROM = kwargs.setdefault('mail_from', "noreply@mbqianbao.com")
        self.PASSWD = kwargs.setdefault('mail_passwd', "Thr-Tc9-qrf-zP5")

    def addimg(self, src, imgid):
        with open(src, 'rb') as fp:
            msgImage = MIMEImage(fp.read())
        msgImage.add_header('Content-ID', imgid)

        return msgImage

    def addMsgText(self, *context):
        return MIMEText(*context)

    def addAttachFile(self, src):
        with open(src, 'rb') as fp:
            try:
                attach = MIMEText(_bencode(fp.read()), 'base64', 'utf-8')
            except Exception as e:
                print(e)
        filename = src.split('/')[-1]
        attach["Context-Type"] = "application/octet-stream"
        attach["Content-Disposition"] = "attachment; filename=" + filename
        attach.replace_header('Content-Transfer-Encoding', 'base64')
        return attach

    def send(self, **kwargs):
        msg = MIMEMultipart('related')
        if kwargs.get('addimg'):
            print('It\'s is a test')
            msg.attach(self.addimg("/Users/Peter/Desktop/中传授权.jpg", "weeklyabc"))

        if kwargs.get('addmsgtext'):
            msg.attach(kwargs.get('addmsgtext'))

        if kwargs.get('addattach'):
            msg.attach(kwargs.get('addattach'))

        msg['Subject'] = Header(self.SUBJECT, "utf-8")
        msg['From'] = self.FROM
        msg['To'] = self.TO
        msg["Accept-Language"] = "zh-CN"
        msg["Accept-Charset"] = "ISO-8859-1,utf-8"
        try:
            server = smtplib.SMTP()
            server.connect(self.HOST, "25")
            server.login(self.FROM, self.PASSWD)
            send_msg = msg.as_string()
            print(send_msg)
            server.sendmail(self.FROM, self.TO, msg.as_string())
            server.quit()
            print("mail sent successful!")
        except Exception as e:
            print("fail "+str(e))

if __name__ == '__main__':
    SM = sendmail(subject='测试邮件')
    img = SM.addimg("/Users/Peter/Desktop/中传授权.jpg", "weeklyabc")
    #msg = SM.addMsgText("<font color=red> 流量中心使用情况日报表 :<br><img src=\"cid:weeklyabc\" border=\"1\"><br>详细内容见附件. </font>", "html", "utf-8")
    msg = SM.addMsgText("测试测试")
    attach = SM.addAttachFile('/Users/Peter/Desktop/xqxq_1.tiff')
    SM.send(addmsgtext=msg, addattach=attach)
