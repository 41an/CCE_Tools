import gmalg
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QRadioButton,
    QGroupBox, QButtonGroup, QTabWidget, QSizePolicy, QSpacerItem, QScrollArea
)

from core.sm2_handler import generate_sm2_keypair, is_valid_sm2_private_key, is_valid_sm2_public_key, calc_sm2_digest_e, \
    is_valid_sm2_uid, encode_rs_to_asn1, convert_signature, extract_rs_from_asn1
from core.utils import  utf82hex, utf82base64, base642hex, base642utf8, \
    hex2base64, hex2utf8


class SM2Tab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.current_msg_format = "UTF-8"
        self.last_msg_format = "UTF-8"

        self.current_uid_format = "UTF-8"
        self.last_uid_format = "UTF-8"

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)              # 整个Tab主布局
        scroll_area = QScrollArea()             # 滚动区域
        scroll_area.setWidgetResizable(True)    # 设置自适应
        # scroll_area.setStyleSheet("border: none;")
        layout.addWidget(scroll_area)           # 滚动区域添加进主布局
        self.setLayout(layout)                  # 应用到Tab

        # 滚动区域内部实际承载内容的 widget 和 layout
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        scroll_area.setWidget(content_widget)

        # ====== [1] 密钥对区域 ====== #
        key_title_layout = QHBoxLayout()
        # key_title_layout.addWidget(QLabel("密钥对:"))
        key_title_layout.addStretch()
        self.btn_generate_key = QPushButton("生成密钥对")
        key_title_layout.addWidget(self.btn_generate_key)
        content_layout.addLayout(key_title_layout)

        key_group = QGroupBox()
        key_layout = QVBoxLayout()

        # 密钥格式 Tab 选择
        self.key_tab = QTabWidget()
        self.pem_tab = QWidget()
        self.hex_tab = QWidget()

        # PEM 输入
        pem_layout = QVBoxLayout()
        self.private_key_pem = QTextEdit()
        self.public_key_pem = QTextEdit()
        pem_layout.addLayout(self.hline("私钥:", self.private_key_pem))
        pem_layout.addLayout(self.hline("公钥:", self.public_key_pem))
        self.pem_tab.setLayout(pem_layout)

        # HEX 输入使用多行文本框
        hex_layout = QVBoxLayout()
        self.private_key_hex = QTextEdit()
        self.public_key_hex = QTextEdit()
        hex_layout.addLayout(self.hline("私钥:", self.private_key_hex))
        hex_layout.addLayout(self.hline("公钥:", self.public_key_hex))
        self.hex_tab.setLayout(hex_layout)

        self.key_tab.addTab(self.hex_tab, "HEX")
        # TODO
        # self.key_tab.addTab(self.pem_tab, "PEM")

        self.key_tab.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        key_layout.addWidget(self.key_tab)
        key_group.setLayout(key_layout)
        content_layout.addWidget(key_group)

        # ====== [2] 消息区域（消息/摘要切换） ====== #
        # content_layout.addWidget(QLabel("加密上下文:"))

        msg_group = QGroupBox()
        msg_layout = QVBoxLayout()

        # 切换选项：消息 / 摘要
        self.crypt_context_tab = QTabWidget()
        self.msg_tab = QWidget()
        self.digest_tab = QWidget()

        # 加密上下文 layout
        msg_tab_layout = QVBoxLayout()

        # 用户标识区
        # uid_format_layout = QHBoxLayout()
        # uid_format_layout.addWidget(QLabel("ID格式\t:"))
        # self.uid_format_btn_group = self.add_radio_buttons_aligned(["UTF-8", "Base64"], uid_format_layout)
        # msg_tab_layout.addLayout(uid_format_layout)

        self.uid_input_utf8 = QLineEdit()
        self.uid_input_base64 = QLineEdit()
        self.uid_input_hex = QLineEdit()
        # self.btn_rm_spaces = QPushButton("去除空格")
        msg_tab_layout.addLayout(self.hline("用户ID\t:", self.uid_input_utf8))
        msg_tab_layout.addLayout(self.hline("BASE64\t:", self.uid_input_base64))
        msg_tab_layout.addLayout(self.hline("HEX\t:", self.uid_input_hex))

        self.msg_tab.setLayout(msg_tab_layout)

        # 空白行
        self.spacer_input = QLineEdit()
        spacer = QSpacerItem(20, self.spacer_input.sizeHint().height(),
                             QSizePolicy.Minimum, QSizePolicy.Fixed)
        msg_tab_layout.addItem(spacer)

        # 消息输入区
        # msg_format_layout = QHBoxLayout()
        # msg_format_layout.addWidget(QLabel("消息格式\t:"))
        # self.msg_format_btn_group = self.add_radio_buttons_aligned(["UTF-8", "Base64"], msg_format_layout)
        # msg_tab_layout.addLayout(msg_format_layout)

        self.msg_input_utf8 = QLineEdit()
        self.msg_input_base64 = QLineEdit()
        self.msg_input_hex = QLineEdit()
        msg_tab_layout.addLayout(self.hline("消息\t:", self.msg_input_utf8))
        msg_tab_layout.addLayout(self.hline("BASE64\t:", self.msg_input_base64))
        msg_tab_layout.addLayout(self.hline("HEX\t:", self.msg_input_hex))

        self.e_input = QLineEdit()
        # 空白行
        msg_tab_layout.addItem(spacer)
        msg_tab_layout.addLayout(self.hline("e值\t:", self.e_input))

        # 摘要处理区
        digest_tab_layout = QVBoxLayout()
        self.digest_input = QLineEdit()
        digest_tab_layout.addLayout(self.hline("摘要输入:", self.digest_input))
        self.digest_tab.setLayout(digest_tab_layout)

        self.crypt_context_tab.addTab(self.msg_tab, "消息")
        # self.crypt_context_tab.addTab(self.digest_tab, "摘要")

        msg_layout.addWidget(self.crypt_context_tab)
        msg_group.setLayout(msg_layout)
        content_layout.addWidget(msg_group)

        # ====== [3] 签名与验签区域 ======
        sig_title_layout = QHBoxLayout()
        # sig_title_layout.addWidget(QLabel("签名值:"))
        sig_title_layout.addStretch()
        self.btn_sign = QPushButton("签名")
        self.btn_verify = QPushButton("验签")
        # self.btn_enable_asn1 = QPushButton("ASN.1")
        # sig_title_layout.addWidget(self.btn_enable_asn1)
        sig_title_layout.addWidget(self.btn_sign)
        sig_title_layout.addWidget(self.btn_verify)
        content_layout.addLayout(sig_title_layout)

        sig_group = QGroupBox()
        sig_layout = QVBoxLayout()

        # 签名格式切换
        self.sig_tab = QTabWidget()
        self.asn1_tab = QWidget()
        self.rs_tab = QWidget()

        self.signature_asn1 = QLineEdit()
        self.asn1_tab.setLayout(self.hline("签名值:", self.signature_asn1))
        self.signature_asn1.setPlaceholderText("hex...")

        self.signature_rs = QLineEdit()
        self.rs_tab.setLayout(self.hline("签名值:", self.signature_rs))
        self.signature_rs.setPlaceholderText("hex...")

        self.sig_tab.addTab(self.asn1_tab, "ASN.1")
        self.sig_tab.addTab(self.rs_tab, "R+S")

        sig_layout.addWidget(self.sig_tab)
        sig_group.setLayout(sig_layout)
        content_layout.addWidget(sig_group)

        # ====== [4] 处理结果展示 ======
        # main_layout.addWidget(QLabel("结果:"))

        result_group = QGroupBox()
        result_layout = QVBoxLayout()

        result_inner_group = QGroupBox()
        result_inner_layout = QVBoxLayout()
        self.result_output = QLineEdit()
        result_inner_layout.addLayout(self.hline("输出结果:", self.result_output))
        result_inner_group.setLayout(result_inner_layout)

        result_layout.addWidget(result_inner_group)
        result_group.setLayout(result_layout)
        content_layout.addWidget(result_group)

        self.setLayout(content_layout)

        # 切换事件绑定
        self.key_tab.currentChanged.connect(self.adjust_key_area_height)

        ##################### 1-密钥对 #####################
        self.btn_generate_key.clicked.connect(self.update_keypair)
        ##################### 1-密钥对 #####################
        #################################################
        #################### 2-消息 ####################
        # ID
        self.uid_input_utf8.setText("1234567812345678")
        self.uid_input_base64.setText("MTIzNDU2NzgxMjM0NTY3OA==")
        self.uid_input_hex.setText("31323334353637383132333435363738")
        # self.uid_format_btn_group.buttonClicked.connect(self.on_uid_format_changed)
        self.uid_input_utf8.textEdited.connect(self.on_uid_input_utf8_changed)
        self.uid_input_base64.textEdited.connect(self.on_uid_input_base64_changed)
        self.uid_input_hex.textEdited.connect(self.on_uid_input_hex_changed)
        # 消息
        # self.msg_format_btn_group.buttonClicked.connect(self.on_msg_format_changed)
        self.msg_input_utf8.textEdited.connect(self.on_msg_input_utf8_changed)
        self.msg_input_base64.textEdited.connect(self.on_msg_input_base64_changed)
        self.msg_input_hex.textEdited.connect(self.on_msg_input_hex_changed)
        #################### 2-消息 ######################
        #################################################
        #################### 3-签名值 ####################
        # 签名
        self.btn_sign.clicked.connect(self.sign)
        # 验签
        self.btn_verify.clicked.connect(self.verify)

        # # RS值 输入框
        # self.signature_rs.textChanged.connect(self.on_signature_rs_changed)
        #################### 3-签名值 ####################
        #################################################
        #################### 4-结果 ####################

        #################### 4-结果 ####################


    def hline(self, label_text, widget):
        layout = QHBoxLayout()
        layout.addWidget(QLabel(label_text))
        layout.addWidget(widget)
        return layout

    def add_radio_buttons_aligned(self, labels, layout):
        btn_group = QButtonGroup(self)
        layout.setSpacing(15)
        for i, label in enumerate(labels):
            btn = QRadioButton(label)
            if i == 0:
                btn.setChecked(True)
            layout.addWidget(btn)
            btn_group.addButton(btn)
        layout.addStretch()
        return btn_group

    def adjust_key_area_height(self):
        self.layout().activate()

    ##################### 1-密钥对 #####################
    def update_keypair(self):
        private_key, public_key = generate_sm2_keypair()
        self.private_key_hex.setText(private_key)
        self.public_key_hex.setText(public_key)

    def get_keypair(self):
        current_tab = self.key_tab.tabText(self.key_tab.currentIndex())
        if current_tab == "HEX":
            return self.private_key_hex.toPlainText(), self.public_key_hex.toPlainText(),
        elif current_tab == "PEM":
            return self.private_key_pem.toPlainText(), self.public_key_pem.toPlainText(),
        else:
            return "get_keypair err", "get_keypair err"

    ##################### 1-密钥对 #####################
    ###################################################
    ##################### 2-消 息 ######################
    def on_uid_input_utf8_changed(self):
        uid = self.uid_input_utf8.text()

        # utf-8 --> hex
        id_text_hex = utf82hex(uid)
        self.uid_input_hex.setText(id_text_hex)
        # utf-8 --> base64
        id_text_base64 = utf82base64(uid)
        self.uid_input_base64.setText(id_text_base64)

    def on_uid_input_base64_changed(self):
        uid = self.uid_input_base64.text()
        # base64 --> hex
        id_text_hex = base642hex(uid)
        self.uid_input_hex.setText(id_text_hex)
        # base64 --> utf-8
        id_text_utf8 = base642utf8(uid)
        self.uid_input_utf8.setText(id_text_utf8)

    def on_uid_input_hex_changed(self):
        uid_hex = self.uid_input_hex.text()
        # hex --> utf-8
        uid_utf8 = hex2utf8(uid_hex)
        self.uid_input_utf8.setText(uid_utf8)
        # hex --> base64
        uid_base64 = hex2base64(uid_hex)
        self.msg_input_base64.setText(uid_base64)

    def on_msg_input_utf8_changed(self):
        msg = self.msg_input_utf8.text()

        # utf-8 --> hex
        id_text_hex = utf82hex(msg)
        self.msg_input_hex.setText(id_text_hex)
        # utf-8 --> base64
        id_text_base64 = utf82base64(msg)
        self.msg_input_base64.setText(id_text_base64)

    def on_msg_input_base64_changed(self):
        msg = self.msg_input_base64.text()
        # base64 --> hex
        id_text_hex = base642hex(msg)
        self.msg_input_hex.setText(id_text_hex)
        # base64 --> utf-8
        id_text_utf8 = base642utf8(msg)
        self.msg_input_utf8.setText(id_text_utf8)

    def on_msg_input_hex_changed(self):
        msg_hex = self.msg_input_hex.text()
        # hex --> utf-8
        msg_utf8 = hex2utf8(msg_hex)
        self.msg_input_utf8.setText(msg_utf8)
        # hex --> base64
        msg_base64 = hex2base64(msg_hex)
        self.msg_input_base64.setText(msg_base64)

    # 获取消息
    def get_msg(self):
        # 获取 消息
        msg = self.msg_input_hex.text().replace(" ", "")
        # msg_tab = self.msg_format_btn_group.checkedButton().text().lower()
        return msg

    def get_uid(self):
        # 获取 用户标识格式 tab
        uid = self.uid_input_hex.text().replace(" ", "")
        # uid_tab = self.uid_format_btn_group.checkedButton().text().lower()
        return uid

    # 获取摘要
    def get_digest(self):
        return self.digest_input.text()

    # 处理 加密上下文 tab
    def get_context(self):
        # 获取消息 tab
        current_tab = self.crypt_context_tab.tabText(self.crypt_context_tab.currentIndex())
        return current_tab

    #################### 2-消息 #####################
    #################################################
    #################### 3-签名值 ####################

    def get_crypt_context(self):
        priv_key, pub_key = self.get_keypair()
        msg = self.get_msg()
        uid = self.get_uid()
        return priv_key, pub_key, msg, uid

    # 签名
    def sign(self):
        self.result_output.setText("")
        priv_key, pub_key, msg, uid = self.get_crypt_context()
        if priv_key == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("私钥不能为空")
            return
        if pub_key == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("公钥不能为空")
            return
        elif msg == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("消息不能为空")
            return
        elif uid == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("用户标识不能为空")
            return

        # 判断私钥是否合规
        valid, res = is_valid_sm2_private_key(priv_key)
        if not valid:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText(res)
            return

        # 判断公钥是否合规
        valid, res = is_valid_sm2_public_key(pub_key)
        if not valid:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText(res)
            return

        # 判断uid是否可以hex解码
        try:
            bytes.fromhex(uid)
        except ValueError as e:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("用户标识有误: " + str(e))
            return
        # 判断uid是否合规
        valid, res = is_valid_sm2_uid(bytes.fromhex(uid))
        if not valid:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText(res)
            return

        #判断msg是否合规
        try:
            bytes.fromhex(msg)
        except ValueError as e:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("消息有误: " + str(e))
            return

        # 计算e值
        try:
            digest_e = calc_sm2_digest_e(uid, bytes.fromhex(msg), pub_key)
            self.e_input.setText(digest_e)
        except Exception as e:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText(f"计算e值失败: {e}")
            return


        sm2 = gmalg.SM2(
            bytes.fromhex(priv_key),
            bytes.fromhex(uid),
            bytes.fromhex(pub_key)
        )

        r, s = sm2.sign(bytes.fromhex(msg))

        # ASN.1
        asn1_signature = encode_rs_to_asn1(r.hex(), s.hex())
        self.signature_asn1.setText(asn1_signature.hex())
        # R+S
        self.signature_rs.setText(r.hex() + s.hex())

        self.result_output.setStyleSheet("color: green;")
        self.result_output.setText("签名计算成功")

    # 验签
    def verify(self):
        self.result_output.setText("")

        priv_key, pub_key, msg, uid = self.get_crypt_context()
        msg_hex = self.msg_input_hex.text().strip()

        # 判断公钥是否合规
        valid, res = is_valid_sm2_public_key(pub_key)
        if not valid:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText(res)
            return

        # 判断uid是否可以hex解码
        try:
            bytes.fromhex(uid)
        except ValueError as e:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("用户标识有误: " + str(e))
            return

        #判断msg是否合规
        try:
            bytes.fromhex(msg)
        except ValueError as e:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("消息有误: " + str(e))
            return

        # 判断uid是否合法
        valid, res = is_valid_sm2_uid(bytes.fromhex(uid))
        if not valid:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText(res)
            return

        # 判断消息是否合法
        try:
            msg_bytes = bytes.fromhex(msg_hex)
        except ValueError:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("非法的消息")
            return

        sm2 = gmalg.SM2(
            bytes.fromhex(""),
            bytes.fromhex(uid),
            bytes.fromhex(pub_key)
        )

        current_tab = self.sig_tab.tabText(self.sig_tab.currentIndex()).lower()
        if current_tab == "asn.1":
            rs = self.signature_asn1.text()
        elif current_tab == "r+s":
            rs = self.signature_rs.text()
        else:
            return "get rs err"

        # 判断 密钥对 是否为空
        if pub_key == "" or pub_key == None:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("公钥不能为空")
            return
        # 判断 加密上下文 是否为空
        if msg == "" or msg == None:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("消息不能为空")
            return
        if uid == "" or uid == None:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("用户标识不能为空")
            return

        # 判断 签名值 是否有效
        if rs == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("签名值不能为空")
            return


        # 转换为标准的ASN.1格式
        rs_ASN1 = convert_signature(rs)
        if "错误" in rs_ASN1:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText(rs_ASN1)
            return
        if rs_ASN1 == False:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("签名值有误")
            return

        r, s = extract_rs_from_asn1(rs_ASN1)

        # if sm2.verify(msg.encode("utf-8"), bytes.fromhex(r), bytes.fromhex(s)):
        if sm2.verify(bytes.fromhex(msg_hex), bytes.fromhex(r), bytes.fromhex(s)):
            self.result_output.setStyleSheet("color: green;")
            self.result_output.setText("签名验证完成：内容与签名匹配")
        else:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("签名验证完成：内容与签名不匹配")

    def on_signature_rs_changed(self):
        print("on_signature_rs_changed in")
        rs = self.signature_rs.text()

        # 转换为ASN.1格式
        rs = convert_signature(rs)
        if "错误" in rs:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText(rs)
            return
        if rs == False:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("签名值有误")
            return
        else:
            self.signature_asn1.setText(rs)

    #################### 3-签名值 ####################
    #################################################
    #################### 4-结果 ####################

    #################### 4-结果 ####################
