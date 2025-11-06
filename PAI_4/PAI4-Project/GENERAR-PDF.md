# Instrucciones para Generar el Informe en PDF

El informe técnico está disponible en los siguientes formatos:
- **PAI4-Informe-Tecnico.md** (Markdown - formato fuente)
- **PAI4-Informe-Tecnico.html** (HTML - visualización en navegador)

## Opción 1: Conversión con Pandoc (Recomendado)

Si tienes Pandoc instalado:

```bash
pandoc PAI4-Informe-Tecnico.md -o PAI4-Informe-Tecnico.pdf \
  --pdf-engine=xelatex \
  -V geometry:margin=2.5cm \
  -V fontsize=11pt \
  --toc
```

### Instalar Pandoc:

- **Linux/Ubuntu:**
  ```bash
  sudo apt-get install pandoc texlive-xetex texlive-fonts-recommended
  ```

- **macOS:**
  ```bash
  brew install pandoc
  brew install --cask mactex
  ```

- **Windows:**
  Descargar desde: https://pandoc.org/installing.html
  Y MiKTeX desde: https://miktex.org/download

## Opción 2: Visual Studio Code

1. Instalar VSCode: https://code.visualstudio.com/
2. Instalar extensión "Markdown PDF"
3. Abrir `PAI4-Informe-Tecnico.md`
4. Clic derecho → "Markdown PDF: Export (pdf)"

## Opción 3: Servicios Online

Subir `PAI4-Informe-Tecnico.md` a alguno de estos servicios:

- https://www.markdowntopdf.com/
- https://md2pdf.netlify.app/
- https://cloudconvert.com/md-to-pdf

## Opción 4: Visualizar HTML

Simplemente abrir `PAI4-Informe-Tecnico.html` en cualquier navegador web y usar la función "Imprimir" → "Guardar como PDF".

## Opción 5: LibreOffice

1. Instalar LibreOffice: https://www.libreoffice.org/
2. Abrir LibreOffice Writer
3. Archivo → Abrir → Seleccionar `PAI4-Informe-Tecnico.md`
4. Archivo → Exportar como → PDF

---

**Nota:** El formato Markdown es perfectamente válido para la entrega. El PDF es opcional pero recomendado para mejor presentación.
