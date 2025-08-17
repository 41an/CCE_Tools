import sys
import binascii
from PyQt5.QtWidgets import (
    QApplication, QLabel, QTextEdit, QVBoxLayout,
    QWidget, QFileDialog, QLineEdit, QMessageBox, QHBoxLayout, QGroupBox
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit

from core.tools_handler import parse_cer_info, get_TBS, pem_to_cer, get_public_key, get_signature, parse_cer_safely
from core.utils import is_within_validity, days_until


class ToolsTab(QWidget):
    def __init__(self):
        super().__init__()
        # self.setWindowTitle("CER 文件分析器")
        self.setAcceptDrops(True)
        # self.resize(600, 500)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # 文件路径显示
        path_group = QGroupBox()
        path_layout = QVBoxLayout()

        path_inner_group = QGroupBox()
        path_inner_layout = QVBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("将 .cer/.crt/.pem 文件拖入此窗口...")
        path_inner_group.setLayout(path_inner_layout)
        path_inner_layout.addLayout(self.hline("文件路径:\t", self.file_path_edit))
        path_layout.addWidget(path_inner_group)
        path_group.setLayout(path_layout)
        layout.addWidget(path_group)


        # 基本信息
        info_group = QGroupBox()
        info_layout = QVBoxLayout()

        info_inner_group = QGroupBox()
        info_inner_layout = QVBoxLayout()
        self.issuer_edit = QLineEdit()
        self.validity_edit = QLineEdit()
        self.deadline_edit = QLineEdit()
        self.signature_algorithm_edit = QLineEdit()
        info_inner_group.setLayout(info_inner_layout)
        info_inner_layout.addLayout(self.hline("颁发机构:\t", self.issuer_edit))
        info_inner_layout.addLayout(self.hline("签名算法:\t", self.signature_algorithm_edit))
        info_inner_layout.addLayout(self.hline("有效日期:\t", self.validity_edit))
        info_inner_layout.addLayout(self.hline("截止日期:\t", self.deadline_edit))
        info_layout.addWidget(info_inner_group)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        # 功能按钮
        btn_sign_layout = QHBoxLayout()
        self.btn_reformat = QPushButton("格式化")
        # self.btn_verify = QPushButton("验签")
        btn_sign_layout.addStretch()
        btn_sign_layout.addWidget(self.btn_reformat)
        # btn_sign_layout.addWidget(self.btn_verify)
        layout.addLayout(btn_sign_layout)

        # 签名值
        signature_group = QGroupBox()
        signature_layout = QVBoxLayout()

        signature_inner_group = QGroupBox()
        signature_inner_layout = QVBoxLayout()
        self.pubkey_algo_edit = QLineEdit()
        self.signature_edit = QTextEdit()
        self.tbs_edit = QTextEdit()
        self.pubkey_edit = QTextEdit()
        signature_inner_group.setLayout(signature_inner_layout)
        signature_inner_layout.addLayout(self.hline("公钥算法:\t", self.pubkey_algo_edit))
        signature_inner_layout.addLayout(self.hline("公钥值:\t", self.pubkey_edit))
        signature_inner_layout.addLayout(self.hline("待验签值:\t", self.tbs_edit))
        signature_inner_layout.addLayout(self.hline("签名值:\t", self.signature_edit))
        signature_layout.addWidget(signature_inner_group)
        signature_group.setLayout(signature_layout)
        layout.addWidget(signature_group)


        # 结果栏
        result_group = QGroupBox()
        result_layout = QVBoxLayout()

        result_inner_group = QGroupBox()
        result_inner_layout = QVBoxLayout()
        self.result_output = QTextEdit()
        result_inner_group.setLayout(result_inner_layout)
        result_inner_layout.addLayout(self.hline("输出结果:\t", self.result_output))
        result_layout.addWidget(result_inner_group)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)



        self.setLayout(layout)

        self.btn_reformat.clicked.connect(self.reformat)

    def hline(self, label_text, widget):
        layout = QHBoxLayout()
        layout.addWidget(QLabel(label_text))
        layout.addWidget(widget)
        return layout

    def _set_result(self, text, color):
        self.result_output.setStyleSheet(f"color: {color};")
        self.result_output.setText(text)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if not urls:
            return
        file_path = urls[0].toLocalFile()


        if not (file_path.lower().endswith(".cer") or file_path.lower().endswith(".crt") or file_path.lower().endswith(".pem")):
            QMessageBox.warning(self, "错误", "仅支持 .cer/.crt/.pem 文件")
            return

        # 处理 pem 格式的证书
        if file_path.lower().endswith(".pem"):
            try:
                file_path = pem_to_cer(file_path)
            except Exception as e:
                self._set_result(f"pem证书读取失败，{e}", "red")
                return

        self.file_path_edit.setText(file_path)

        # 解决win环境下 openssl 无法处理带中文字符的证书
        result = parse_cer_safely(file_path, parse_cer_info)
        # result = parse_cer_info(file_path)

        if not result.get("success"):
            QMessageBox.critical(self, "解析失败", result.get("error", "未知错误"))
            return

        public_key = ""
        tbs = ""
        signature = ""
        try:
            public_key = get_public_key(file_path)
        except Exception as e:
            self._set_result(f"提取公钥，{e}", "red")
        try:
            tbs = get_TBS(file_path)
        except Exception as e:
            self._set_result(f"提取带验签数据失败，{e}", "red")
        try:
            signature = get_signature(file_path)
        except Exception as e:
            self._set_result(f"提取签名值失败，{e}", "red")

        # 按断算法有效性
        signature_effective = True
        self.signature_algorithm_edit.setStyleSheet("color:green")
        if "sm2" not in result.get("signature_algorithm", "").lower() and "sm3" not in result.get("signature_algorithm", "").lower():
            signature_effective = False

        # 判断时间有效性
        self.validity_edit.setStyleSheet("color:green")
        deadline = days_until(result.get('not_after', ""))
        if deadline < 1:
            self.validity_edit.setStyleSheet("color:red")

        # 显示数据
        if not signature_effective:
            self.signature_algorithm_edit.setStyleSheet("color:red")
        self.signature_algorithm_edit.setText(result.get("signature_algorithm", ""))
        self.issuer_edit.setText(result.get("issuer", ""))

        self.validity_edit.setText(result.get('not_before',  "")+"至"+result.get('not_after', ""))
        self.deadline_edit.setText(str(deadline)+"天")

        self.pubkey_algo_edit.setText(result.get("public_key_algorithm", ""))

        self.pubkey_edit.setText(public_key)
        if public_key != "":
            self._set_result("公钥提取成功\n注意：此公钥仅可用于验证下一级证书", "green")
        self.tbs_edit.setText(tbs)
        self.signature_edit.setText(signature)


    def reformat(self):
        self._set_result("格式化功能有待开发...", "orange")