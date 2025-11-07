"""
Click Protection - Export Modülü

Analiz sonuçlarını PDF, CSV ve JSON formatlarında dışa aktarır.
"""

import json
import csv
import os
from datetime import datetime
from tkinter import filedialog, messagebox

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfbase.pdfmetrics import registerFontFamily
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class ExportManager:
    """Analiz sonuçlarını dışa aktarma yöneticisi"""
    
    def __init__(self, script_dir):
        self.script_dir = script_dir
        self.reports_dir = os.path.join(script_dir, "data", "reports")
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def export_results(self, analysis_data, format_type='pdf'):
        """
        Analiz sonuçlarını belirtilen formatta dışa aktarır.
        
        Args:
            analysis_data: Analiz sonuçları dict
            format_type: 'pdf', 'csv', veya 'json'
        
        Returns:
            str: Kaydedilen dosya yolu veya None
        """
        if format_type == 'pdf':
            return self._export_pdf(analysis_data)
        elif format_type == 'csv':
            return self._export_csv(analysis_data)
        elif format_type == 'json':
            return self._export_json(analysis_data)
        else:
            return None
    
    def _export_pdf(self, analysis_data):
        """PDF formatında dışa aktar"""
        if not REPORTLAB_AVAILABLE:
            return None
        
        try:
            # Türkçe karakter desteği için font ayarları
            # DejaVu Sans font'u Türkçe karakterleri destekler
            try:
                # Windows'ta DejaVu Sans bulunmaya çalış
                font_paths = [
                    'C:/Windows/Fonts/dejavusans.ttf',
                    'C:/Windows/Fonts/arial.ttf',
                    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
                ]
                font_path = None
                for path in font_paths:
                    if os.path.exists(path):
                        font_path = path
                        break
                
                if font_path:
                    pdfmetrics.registerFont(TTFont('DejaVu', font_path))
                    font_name = 'DejaVu'
                else:
                    # Font bulunamazsa varsayılan font kullan
                    font_name = 'Helvetica'
            except:
                font_name = 'Helvetica'
            
            # Dosya adı oluştur
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            url_safe = analysis_data.get('url', 'unknown').replace('http://', '').replace('https://', '').replace('/', '_')[:50]
            filename = f"ClickProtection_Report_{url_safe}_{timestamp}.pdf"
            filepath = os.path.join(self.reports_dir, filename)
            
            # PDF oluştur - Modern margin'ler
            doc = SimpleDocTemplate(filepath, pagesize=A4, 
                                   rightMargin=60, leftMargin=60,
                                   topMargin=60, bottomMargin=50)
            story = []
            styles = getSampleStyleSheet()
            
            # Modern renk paleti
            primary_color = colors.HexColor('#1E3A8A')
            secondary_color = colors.HexColor('#3B82F6')
            success_color = colors.HexColor('#10B981')
            warning_color = colors.HexColor('#F59E0B')
            danger_color = colors.HexColor('#EF4444')
            light_gray = colors.HexColor('#F3F4F6')
            dark_gray = colors.HexColor('#6B7280')
            
            # Türkçe karakter desteği için özel stiller - Daha modern
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontName=font_name,
                fontSize=28,
                textColor=primary_color,
                spaceAfter=12,
                alignment=TA_CENTER,
                leading=34
            )
            
            subtitle_style = ParagraphStyle(
                'CustomSubtitle',
                parent=styles['Normal'],
                fontName=font_name,
                fontSize=12,
                textColor=dark_gray,
                spaceAfter=25,
                alignment=TA_CENTER,
                leading=16
            )
            
            heading2_style = ParagraphStyle(
                'CustomHeading2',
                parent=styles['Heading2'],
                fontName=font_name,
                fontSize=16,
                textColor=primary_color,
                spaceAfter=12,
                leading=20,
                borderWidth=0,
                borderPadding=8,
                backColor=light_gray
            )
            
            normal_style = ParagraphStyle(
                'CustomNormal',
                parent=styles['Normal'],
                fontName=font_name,
                fontSize=10,
                leading=14,
                encoding='utf-8',
                textColor=colors.HexColor('#111827')
            )
            
            info_box_style = ParagraphStyle(
                'InfoBox',
                parent=normal_style,
                fontName=font_name,
                fontSize=10,
                leading=14,
                backColor=light_gray,
                borderWidth=1,
                borderColor=colors.HexColor('#E5E7EB'),
                borderPadding=10,
                leftIndent=5,
                rightIndent=5
            )
            
            # Başlık - Modern tasarım
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph("🛡️ Click Protection", title_style))
            story.append(Paragraph("URL/IP Güvenlik Analiz Raporu", subtitle_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Analiz bilgileri - Modern info box
            timestamp_str = analysis_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            url_str = analysis_data.get('url', 'N/A')
            domain_str = analysis_data.get('domain', 'N/A')
            
            # Info box içinde analiz bilgileri
            info_text = f"""
            <b>Analiz Tarihi:</b> {timestamp_str}<br/>
            <b>Analiz Edilen URL/IP:</b> {url_str}<br/>
            <b>Domain:</b> {domain_str}
            """
            story.append(Paragraph(info_text, info_box_style))
            story.append(Spacer(1, 0.25*inch))
            
            # Risk skoru - Modern badge tasarımı
            score = analysis_data.get('risk_score', 0)
            status = analysis_data.get('risk_status', 'Bilinmeyen')
            
            # Risk seviyesine göre renk
            if score <= 20:
                risk_color = success_color
                risk_bg = colors.HexColor('#D1FAE5')
            elif score <= 60:
                risk_color = warning_color
                risk_bg = colors.HexColor('#FEF3C7')
            else:
                risk_color = danger_color
                risk_bg = colors.HexColor('#FEE2E2')
            
            risk_style = ParagraphStyle(
                'RiskStyle',
                parent=styles['Heading1'],
                fontName=font_name,
                fontSize=24,
                textColor=risk_color,
                spaceAfter=8,
                alignment=TA_CENTER,
                backColor=risk_bg,
                borderWidth=2,
                borderColor=risk_color,
                borderPadding=15,
                leading=28
            )
            
            story.append(Paragraph(f"Risk Skoru: <b>{score}%</b> - {status}", risk_style))
            story.append(Spacer(1, 0.25*inch))
            
            # Bulgular - Modern tablo tasarımı
            story.append(Paragraph("🔍 Güvenlik Bulguları", heading2_style))
            story.append(Spacer(1, 0.15*inch))
            
            issues = analysis_data.get('issues', [])
            if issues:
                issue_data = [['#', 'Bulgular', 'Detay']]
                for i, (issue_text, detail_key) in enumerate(issues, 1):
                    # Emoji'leri kaldır ve temizle
                    issue_clean = issue_text.replace('🔴', '').replace('🟠', '').replace('🟡', '').replace('🟢', '').replace('ℹ️', '').replace('🚫', '').replace('✅', '').replace('🔎', '').replace('⚠️', '').strip()
                    detail = analysis_data.get('issue_details', {}).get(detail_key, {}).get('text', '') if detail_key else ''
                    # Türkçe karakterleri koru - Daha uzun metin
                    issue_data.append([str(i), issue_clean[:85], detail[:100] if detail else '-'])
                
                issue_table = Table(issue_data, colWidths=[0.5*inch, 4*inch, 2.5*inch], repeatRows=1)
                table_style_list = [
                    # Header
                    ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTNAME', (0, 0), (-1, 0), font_name if font_name != 'Helvetica' else 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                    ('TOPPADDING', (0, 0), (-1, 0), 10),
                    # Data rows
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('FONTNAME', (0, 1), (-1, -1), font_name),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_gray]),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 1), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 10),
                ]
                
                issue_table.setStyle(TableStyle(table_style_list))
                story.append(issue_table)
            else:
                story.append(Paragraph("✅ Herhangi bir güvenlik bulgusu tespit edilmedi.", normal_style))
            
            story.append(Spacer(1, 0.3*inch))
            
            # VirusTotal sonuçları - Modern tasarım
            vt_data = analysis_data.get('virustotal', {})
            if vt_data:
                story.append(Spacer(1, 0.2*inch))
                story.append(Paragraph("🦠 VirusTotal Sonuçları", heading2_style))
                story.append(Spacer(1, 0.15*inch))
                
                vt_info = [
                    ['Kategori', 'Sonuç'],
                    ['🟢 Temiz', str(vt_data.get('harmless', 0))],
                    ['🟠 Şüpheli', str(vt_data.get('suspicious', 0))],
                    ['🔴 Zararlı', str(vt_data.get('malicious', 0))],
                    ['⚪ Tespit Edilmemiş', str(vt_data.get('undetected', 0))],
                    ['📊 Toplam Tarama', str(vt_data.get('total_scans', 0))],
                ]
                
                vt_table = Table(vt_info, colWidths=[2.5*inch, 1.5*inch])
                vt_table_style = [
                    # Header
                    ('BACKGROUND', (0, 0), (-1, 0), secondary_color),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('FONTNAME', (0, 0), (-1, 0), font_name if font_name != 'Helvetica' else 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), font_name),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                    ('TOPPADDING', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                    # Data rows
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_gray]),
                ]
                
                vt_table.setStyle(TableStyle(vt_table_style))
                story.append(vt_table)
            
            # Alt bilgi - Modern footer
            story.append(Spacer(1, 0.4*inch))
            footer_style = ParagraphStyle(
                'FooterStyle',
                parent=normal_style,
                fontSize=8,
                textColor=dark_gray,
                alignment=TA_CENTER,
                borderWidth=1,
                borderColor=colors.HexColor('#E5E7EB'),
                borderPadding=8,
                backColor=light_gray
            )
            footer_text = f"""
            Bu rapor <b>Click Protection</b> tarafından otomatik olarak oluşturulmuştur.<br/>
            <i>Rapor oluşturulma zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>
            """
            story.append(Paragraph(footer_text, footer_style))
            
            # PDF'i oluştur
            doc.build(story)
            return filepath
            
        except Exception as e:
            print(f"PDF export hatası: {e}")
            return None
    
    def _export_csv(self, analysis_data):
        """CSV formatında dışa aktar"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            url_safe = analysis_data.get('url', 'unknown').replace('http://', '').replace('https://', '').replace('/', '_')[:50]
            filename = f"ClickProtection_Report_{url_safe}_{timestamp}.csv"
            filepath = os.path.join(self.reports_dir, filename)
            
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Başlık
                writer.writerow(['Click Protection - Güvenlik Analiz Raporu'])
                writer.writerow([])
                
                # Genel bilgiler
                writer.writerow(['Analiz Tarihi', analysis_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))])
                writer.writerow(['URL/IP', analysis_data.get('url', 'N/A')])
                writer.writerow(['Domain', analysis_data.get('domain', 'N/A')])
                writer.writerow(['Risk Skoru', f"{analysis_data.get('risk_score', 0)}%"])
                writer.writerow(['Risk Durumu', analysis_data.get('risk_status', 'N/A')])
                writer.writerow([])
                
                # Bulgular
                writer.writerow(['Bulgular'])
                writer.writerow(['#', 'Bulgular', 'Detay'])
                
                issues = analysis_data.get('issues', [])
                for i, (issue_text, detail_key) in enumerate(issues, 1):
                    issue_clean = issue_text.replace('🔴', '').replace('🟠', '').replace('🟡', '').replace('🟢', '').replace('ℹ️', '').replace('🚫', '').replace('✅', '').strip()
                    detail = analysis_data.get('issue_details', {}).get(detail_key, {}).get('text', '') if detail_key else ''
                    writer.writerow([i, issue_clean, detail])
                
                writer.writerow([])
                
                # VirusTotal
                vt_data = analysis_data.get('virustotal', {})
                if vt_data:
                    writer.writerow(['VirusTotal Sonuçları'])
                    writer.writerow(['Zararlı', vt_data.get('malicious', 0)])
                    writer.writerow(['Şüpheli', vt_data.get('suspicious', 0)])
                    writer.writerow(['Temiz', vt_data.get('harmless', 0)])
                    writer.writerow(['Tespit Edilmemiş', vt_data.get('undetected', 0)])
                    writer.writerow(['Toplam Tarama', vt_data.get('total_scans', 0)])
            
            return filepath
            
        except Exception as e:
            print(f"CSV export hatası: {e}")
            return None
    
    def _export_json(self, analysis_data):
        """JSON formatında dışa aktar"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            url_safe = analysis_data.get('url', 'unknown').replace('http://', '').replace('https://', '').replace('/', '_')[:50]
            filename = f"ClickProtection_Report_{url_safe}_{timestamp}.json"
            filepath = os.path.join(self.reports_dir, filename)
            
            # JSON'a çevrilebilir formata getir
            export_data = {
                'report_info': {
                    'timestamp': analysis_data.get('timestamp', datetime.now().isoformat()),
                    'tool': 'Click Protection',
                    'version': '1.0'
                },
                'analysis': {
                    'url': analysis_data.get('url', ''),
                    'domain': analysis_data.get('domain', ''),
                    'risk_score': analysis_data.get('risk_score', 0),
                    'risk_status': analysis_data.get('risk_status', ''),
                },
                'issues': [
                    {
                        'text': issue[0],
                        'detail_key': issue[1],
                        'detail': analysis_data.get('issue_details', {}).get(issue[1], {}).get('text', '') if issue[1] else ''
                    }
                    for issue in analysis_data.get('issues', [])
                ],
                'virustotal': analysis_data.get('virustotal', {}),
            }
            
            with open(filepath, 'w', encoding='utf-8') as jsonfile:
                json.dump(export_data, jsonfile, ensure_ascii=False, indent=2)
            
            return filepath
            
        except Exception as e:
            print(f"JSON export hatası: {e}")
            return None

