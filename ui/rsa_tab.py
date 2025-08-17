import base64

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QRadioButton,
    QGroupBox, QButtonGroup, QTabWidget, QSizePolicy, QSpacerItem, QScrollArea, QComboBox
)
from PyQt5.QtGui import QIntValidator

from core.rsa_handler import RSAUtil, \
    extract_public_key_from_private, convert_private_key_auto, convert_public_key_auto, is_valid_rsa_pem_private_key, \
    is_valid_rsa_pem_public_key, is_valid_rsa_der_private_key, is_valid_rsa_private_key, is_valid_rsa_public_key, \
    der_to_pkcs8_priv, der_to_spki_pub
from core.utils import  hex2utf8, hex2base64, utf82base64, utf82hex, \
    base642hex, base642utf8

STEP = 1024
MIN_VALUE = 1024

allowed_hash_algs = {
            'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
            'md5', 'blake2b', 'blake2s',
            'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512'
        }

allowed_padding_mode = {
            'pkcs1v15', 'pss'
        }
class RSATab(QWidget):
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
        # 提示文本
        key_title_layout = QHBoxLayout()
        # key_title_layout.addWidget(QLabel("密钥对:"))
        self.btn_change_priv_key_format = QPushButton("priv")
        self.btn_change_pub_key_format = QPushButton("pub")
        # key_title_layout.addWidget(self.btn_change_priv_key_format )
        key_title_layout.addWidget(self.btn_change_priv_key_format )
        key_title_layout.addWidget(self.btn_change_pub_key_format )

        # self.btn_generate_key = QPushButton("生成密钥对")
        key_title_layout.addStretch()
        # 密钥长度
        self.step_input = StepInputWidget()
        key_title_layout.addWidget(self.step_input)

        # 生成密钥对
        self.btn_generate_key = QPushButton("生成密钥对")
        key_title_layout.addWidget(self.btn_generate_key)
        content_layout.addLayout(key_title_layout)

        key_group = QGroupBox()
        key_layout = QVBoxLayout()

        # 密钥格式 Tab 选择
        self.key_tab = QTabWidget()
        # self.pkcs1_tab = QWidget()
        self.PKCS_SPKI_tab = QWidget()

        # PKCS_SPKI 格式 TAB
        PKCS_SPKI_layout = QVBoxLayout()
        self.private_key_PKCS = QTextEdit()
        # self.private_key_PKCS.setPlaceholderText("PKCS#1 or PKCS#8")
        self.public_key_SPKI = QTextEdit()
        # self.public_key_SPKI.setPlaceholderText("SPKI")

        PKCS_SPKI_layout.addLayout(self.hline("私钥:", self.private_key_PKCS))
        PKCS_SPKI_layout.addLayout(self.hline("公钥:", self.public_key_SPKI))
        self.PKCS_SPKI_tab.setLayout(PKCS_SPKI_layout)

        # DER 格式 TAB
        # pem_layout = QVBoxLayout()
        # self.private_key_pem = QTextEdit()
        # self.public_key_pem = QTextEdit()
        # pem_layout.addLayout(self.hline("私钥:", self.private_key_pem))
        # pem_layout.addLayout(self.hline("公钥:", self.public_key_pem))
        # self.pem_tab.setLayout(pem_layout)

        # self.key_tab.addTab(self.pkcs1_tab, "PKCS#1")
        self.key_tab.addTab(self.PKCS_SPKI_tab, "HEX")

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
        # self.digest_tab = QWidget()

        # 加密上下文 layout
        msg_tab_layout = QVBoxLayout()


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
        msg_tab_layout.addLayout(self.hline("UTF-8\t:", self.msg_input_utf8))
        msg_tab_layout.addLayout(self.hline("BASE64\t:", self.msg_input_base64))
        msg_tab_layout.addLayout(self.hline("HEX\t:", self.msg_input_hex))

        self.e_input = QLineEdit()


        self.crypt_context_tab.addTab(self.msg_tab, "消息")

        msg_layout.addWidget(self.crypt_context_tab)
        msg_group.setLayout(msg_layout)
        content_layout.addWidget(msg_group)

        # ====== [3] 签名与验签区域 ======
        # 按钮栏
        func_title_layout = QHBoxLayout()
        func_title_layout.addStretch()
        self.btn_sign = QPushButton("签名")
        self.btn_verify = QPushButton("验签")
        func_title_layout.addWidget(self.btn_sign)
        func_title_layout.addWidget(self.btn_verify)
        content_layout.addLayout(func_title_layout)

        # 签名控件区域
        func_group = QGroupBox()
        func_layout = QVBoxLayout()

        # 签名格式切换
        self.func_tab = QTabWidget()
        self.details_tab = QWidget()

        # 创建组件
        self.signature = QLineEdit()
        self.signature.setPlaceholderText("签名值 hex...")

        self.paddind_mode_combo = QComboBox()
        self.paddind_mode_combo.addItems(["PKCS1V15", "PSS"])
        self.paddind_mode_combo.setCurrentText("PKCS1V15")


        self.hash_alg_combo = QComboBox()
        self.hash_alg_combo.addItems(["SHA1","SHA224","SHA256","SHA384","SHA512","MD5","BLAKE2b","BLAKE2s","SHA3_224","SHA3_256","SHA3_384","SHA3_512"])
        self.hash_alg_combo.setCurrentText("SHA256")

        # 嵌入纵向布局
        asn1_layout = QVBoxLayout()
        asn1_layout.addLayout(self.hline("paddind\t:", self.paddind_mode_combo))
        asn1_layout.addLayout(self.hline("hash\t:", self.hash_alg_combo))
        asn1_layout.addLayout(self.hline("签名值\t:", self.signature))


        # 设置布局
        self.details_tab.setLayout(asn1_layout)
        self.func_tab.addTab(self.details_tab, "签名验签")

        # 总体嵌入签名区域
        func_layout.addWidget(self.func_tab)
        func_group.setLayout(func_layout)
        content_layout.addWidget(func_group)

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


        ##################### 1-密钥对 #####################
        self.btn_change_priv_key_format.clicked.connect(self.change_priv_key_format)
        self.btn_change_pub_key_format.clicked.connect(self.change_pub_key_format)
        self.btn_generate_key.clicked.connect(self.update_keypair)
        ##################### 2-消息 #####################
        self.msg_input_utf8.textEdited.connect(self.on_msg_input_utf8_changed)
        self.msg_input_base64.textEdited.connect(self.on_msg_input_base64_changed)
        self.msg_input_hex.textEdited.connect(self.on_msg_input_hex_changed)
        ##################### 3-消息 #####################
        # 签名
        self.btn_sign.clicked.connect(self.sign)
        # 验签
        self.btn_verify.clicked.connect(self.verify)
        ##################### 4-结果 #####################

    # UI函数

    def _apply_button_style(self, button):
        button.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                font-size: 18px;
            }
            QPushButton:hover {
                color: #0078d7;  /* Windows 蓝 或改为 #1E90FF 更现代 */
            }
        """)

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

    # -------------------- BEGIN 1-密钥对 --------------------#
    def update_keypair(self):
        step_input_value = self.step_input.get_value()
        rsa_util = RSAUtil(key_size=step_input_value, public_exponent=65537)

        private_pem = rsa_util.export_private_key(encoding='DER', format='PKCS8')
        public_pem = rsa_util.export_public_key(encoding='DER')

        self.private_key_PKCS.setText(private_pem.hex())
        self.public_key_SPKI.setText(public_pem.hex())

    # 获取秘钥
    def get_keypair(self):
        return self.private_key_PKCS.toPlainText(), self.public_key_SPKI.toPlainText(),

    def change_priv_key_format(self):
        self.result_output.setText("")
        priv_key, pub_key = self.get_keypair()

        if priv_key.strip() == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("私钥为空，无法转换格式")
            return

        try:
            res = convert_private_key_auto(priv_key.encode("utf-8"))

            self.private_key_PKCS.setText(res)
            self.result_output.setStyleSheet("color: green;")
            self.result_output.setText("私钥格式转化成功")
        except Exception as e:
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText(f"转换失败：{str(e)}")


    def change_pub_key_format(self):
        self.result_output.setText("")
        priv_key, pub_key = self.get_keypair()

        try:
            if not priv_key and not pub_key:
                self._set_result("私钥和公钥均为空，无法转换格式", "red")
                return

            # 1. 仅提供私钥，尝试提取公钥
            if priv_key and not pub_key:
                format = is_valid_rsa_private_key(priv_key)
                if format == "der":
                    priv_key = convert_private_key_auto(priv_key.encode("utf-8"))

                format = is_valid_rsa_private_key(priv_key)
                if format == "pem":
                    pub_key_der = extract_public_key_from_private(priv_key.encode("utf-8"))
                    pub_key_pem = convert_public_key_auto(pub_key_der)
                    self.public_key_SPKI.setText(pub_key_pem.strip())
                    self._set_result("提取公钥成功", "green")
                else:
                    self._set_result("非法私钥", "red")

                return

            # 2. 提供公钥，尝试格式转换
            if pub_key:
                res = convert_public_key_auto(pub_key.encode("utf-8"))
                self.public_key_SPKI.setText(res)
                self._set_result("公钥格式转换成功", "green")
                return

        except Exception as e:
            self._set_result(f"处理失败: {e}", "red")

    def _set_result(self, text, color):
        self.result_output.setStyleSheet(f"color: {color};")
        self.result_output.setText(text)
    # -------------------- END 1-密钥对 --------------------#


    # -------------------- BEGIN 2-消息 --------------------#
    # 消息 输入框 变动
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
        msg = self.msg_input_hex.text().replace(" ", "")
        return msg

    # 获取签名相关配置
    def get_signature_config(self):
        padding_mode = self.paddind_mode_combo.currentText()
        hash_alg = self.hash_alg_combo.currentText()
        signature = self.signature.text()
        return padding_mode,hash_alg,signature
    # -------------------- END 2-消息 --------------------#

    # -------------------- BEGIN 3-签名验签 --------------------#
    def sign(self):
        self.result_output.setText("")
        private_key , public_key = self.get_keypair()
        msg = self.get_msg()
        padding_mode,hash_alg,signature = self.get_signature_config()

        if private_key == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("私钥不能为空")
            return
        elif msg == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("消息不能为空")
            return
        elif padding_mode == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("填充模式不能为空")
            return
        elif padding_mode.lower() not in allowed_padding_mode:
                raise ValueError(f"不支持的填充格式: {padding_mode}")
        elif hash_alg == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("Hash算法不能为空")
            return
        elif hash_alg.lower() not in allowed_hash_algs:
                raise ValueError(f"不支持的哈希算法: {hash_alg}")

        try:
            bytes.fromhex(msg)
        except Exception as e:

            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("16进制的消息格式有误")
            return

        # 签名
        format = is_valid_rsa_private_key(private_key.encode())

        if format == "der":
            private_key = der_to_pkcs8_priv(bytes.fromhex(private_key)).decode("utf-8")
        if format == "err":
            self._set_result("私钥有误","red")

        try:
            rsa_util = RSAUtil.from_pem(private_key.encode())
            signature = rsa_util.sign(bytes.fromhex(msg), padding_mode=padding_mode, hash_alg=hash_alg)
        except Exception as e:
            self._set_result(f"签名失败，{e}","red")
            return

        self.signature.setText(signature.hex())
        self._set_result("签名计算成功", "green")

    # 验签
    def verify(self):
        self.result_output.setText("")
        private_key , public_key = self.get_keypair()
        msg = self.get_msg()
        padding_mode,hash_alg,signature = self.get_signature_config()

        if private_key == "" and public_key == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("至少提供一个私钥或者公钥")
            return
        elif msg == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("消息不能为空")
            return
        elif padding_mode == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("填充模式不能为空")
            return
        elif padding_mode.lower() not in allowed_padding_mode:
                raise ValueError(f"不支持的填充格式: {padding_mode}")
        elif hash_alg == "":
            self.result_output.setStyleSheet("color: red;")
            self.result_output.setText("Hash算法不能为空")
            return
        elif hash_alg.lower() not in allowed_hash_algs:
                raise ValueError(f"不支持的哈希算法: {hash_alg}")

        if public_key == "" and private_key != "":
            public_key = "\n".join(
                line for line in extract_public_key_from_private(private_key.encode()).decode("utf-8").splitlines() if
                line.strip())
            self.public_key_SPKI.setText(public_key)

        try:
            bytes.fromhex(msg)
        except Exception as e:
            self._set_result("16进制的消息格式有误", "red")
            return

        try:
            bytes.fromhex(signature)
        except Exception as e:
            self._set_result("16进制的签名格式有误", "red")
            return

        format = is_valid_rsa_public_key(public_key.encode())
        if format == "der":
            public_key = der_to_spki_pub(bytes.fromhex(public_key)).decode("utf-8")
        if format == "err":
            self._set_result(f"公钥非法","red")
            return

        try:
            rsa_util = RSAUtil.from_pem(public_key.encode())
            res = rsa_util.verify(bytes.fromhex(msg), bytes.fromhex(signature), padding_mode=padding_mode, hash_alg=hash_alg)
        except Exception as e:
            self._set_result(f"签名失败，{e}","red")
            return

        if res:
            self._set_result(f"签名验证完成：内容与签名匹配","green")
        else:
            self._set_result("签名验证完成：内容与签名不匹配","red")
    # -------------------- END 3-签名验签 --------------------#

class StepInputWidget(QWidget):
    def __init__(self, step=1024, minimum=1024, parent=None):
        super().__init__(parent)
        self.step = step
        self.minimum = minimum

        self.input = QLineEdit(str(minimum))
        self.input.setFixedWidth(60)
        self.input.setAlignment(Qt.AlignCenter)
        self.input.setValidator(QIntValidator(minimum, 10 ** 9))

        self.btn_minus = QPushButton("-")
        self.btn_plus = QPushButton("+")
        self.btn_minus.setFixedSize(20, 20)
        self.btn_plus.setFixedSize(20, 20)

        # 设置透明背景（仅显示符号）
        for btn in (self.btn_minus, self.btn_plus):
            btn.setStyleSheet("QPushButton { background-color: transparent; border: none; }")

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)  # 去掉内边距
        layout.setSpacing(2)  # 控件之间的间隔

        layout.addWidget(self.btn_minus)
        layout.addWidget(self.input)
        layout.addWidget(self.btn_plus)

        self.setLayout(layout)

        self.btn_minus.clicked.connect(self.decrease)
        self.btn_plus.clicked.connect(self.increase)

    def increase(self):
        val = max(int(self.input.text()), self.minimum)
        self.input.setText(str(val + self.step))

    def decrease(self):
        val = max(int(self.input.text()), self.minimum)
        val = max(val - self.step, self.minimum)
        self.input.setText(str(val))

    def get_value(self):
        try:
            return int(self.input.text())
        except ValueError:
            return self.minimum