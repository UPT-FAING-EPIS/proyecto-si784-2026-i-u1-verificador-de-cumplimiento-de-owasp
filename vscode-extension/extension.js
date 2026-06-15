const vscode = require('vscode');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

// Umbral máximo de tamaño de archivo para evitar problemas de rendimiento (2 MB)
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;

let statusBarItem;
let extensionPath;

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    extensionPath = context.extensionPath;
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('owasp-verificator');
    context.subscriptions.push(diagnosticCollection);

    // Inicializar indicador en la barra de estado
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    context.subscriptions.push(statusBarItem);

    // Registrar comando para escaneo manual
    let scanCommand = vscode.commands.registerCommand('owasp-verificator.scanFile', () => {
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor) {
            runScan(activeEditor.document, diagnosticCollection);
        } else {
            vscode.window.showInformationMessage('No hay ningún archivo activo para analizar.');
        }
    });
    context.subscriptions.push(scanCommand);

    // Eventos de activación
    vscode.workspace.onDidOpenTextDocument(doc => runScan(doc, diagnosticCollection), null, context.subscriptions);
    vscode.workspace.onDidSaveTextDocument(doc => runScan(doc, diagnosticCollection), null, context.subscriptions);
    
    // Escaneo al cambiar de archivo activo
    vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor) {
            runScan(editor.document, diagnosticCollection);
        } else {
            statusBarItem.hide();
        }
    }, null, context.subscriptions);

    // Limpiar diagnósticos al cerrar archivos
    vscode.workspace.onDidCloseTextDocument(doc => {
        diagnosticCollection.delete(doc.uri);
    }, null, context.subscriptions);

    // Ejecutar escaneo inicial si ya hay un archivo abierto
    if (vscode.window.activeTextEditor) {
        runScan(vscode.window.activeTextEditor.document, diagnosticCollection);
    }
}

/**
 * Ejecuta el script cli.py y publica los hallazgos en VS Code
 * @param {vscode.TextDocument} document 
 * @param {vscode.DiagnosticCollection} collection 
 */
function runScan(document, collection) {
    // Solo escanear archivos guardados en disco (scheme 'file')
    if (document.uri.scheme !== 'file') {
        statusBarItem.hide();
        return;
    }

    // Comprobación de seguridad por tamaño de archivo para evitar retrasos
    try {
        const stats = fs.statSync(document.uri.fsPath);
        if (stats.size > MAX_FILE_SIZE_BYTES) {
            statusBarItem.hide();
            return;
        }
    } catch (err) {
        statusBarItem.hide();
        return;
    }

    const cliPath = path.join(extensionPath, 'cli.py');

    // Verificar si cli.py existe en la extensión
    if (!fs.existsSync(cliPath)) {
        console.error(`Error: No se encuentra cli.py en la ruta: ${cliPath}`);
        statusBarItem.hide();
        return;
    }

    // Determinar directorio de trabajo
    let cwd = path.dirname(document.uri.fsPath);
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (workspaceFolder) {
        cwd = workspaceFolder.uri.fsPath;
    }

    // Leer ruta de Python configurada por el usuario
    const config = vscode.workspace.getConfiguration('owaspVerificator');
    const pythonPath = config.get('pythonPath') || 'python';

    // Mostrar estado de escaneo
    statusBarItem.text = '$(sync~spin) OWASP: Analizando...';
    statusBarItem.tooltip = 'Ejecutando verificador de cumplimiento OWASP';
    statusBarItem.color = undefined;
    statusBarItem.show();

    const command = `"${pythonPath}" "${cliPath}" "${document.uri.fsPath}"`;

    exec(command, { cwd: cwd }, (error, stdout, stderr) => {
        if (error) {
            console.error(`OWASP Verificator CLI Error: ${stderr || error.message}`);
            statusBarItem.text = '$(error) OWASP: Error de análisis';
            statusBarItem.tooltip = `Error al ejecutar cli.py:\n${stderr || error.message}`;
            statusBarItem.color = new vscode.ThemeColor('statusBarItem.errorForeground');
            return;
        }

        try {
            const findings = JSON.parse(stdout);
            
            if (findings.error) {
                console.error(`OWASP Verificator scan error in JSON: ${findings.error}`);
                statusBarItem.text = '$(error) OWASP: Error en JSON';
                statusBarItem.tooltip = findings.error;
                statusBarItem.color = new vscode.ThemeColor('statusBarItem.errorForeground');
                return;
            }

            updateDiagnostics(document, findings, collection);
            updateStatusBar(findings);

        } catch (e) {
            console.error(`OWASP Verificator parse failed: ${e.message}. Output: ${stdout}`);
            statusBarItem.text = '$(error) OWASP: Error de parseo';
            statusBarItem.tooltip = `No se pudo interpretar el resultado JSON del escáner.`;
            statusBarItem.color = new vscode.ThemeColor('statusBarItem.errorForeground');
        }
    });
}

/**
 * @param {vscode.TextDocument} document 
 * @param {Array} findings 
 * @param {vscode.DiagnosticCollection} collection 
 */
function updateDiagnostics(document, findings, collection) {
    collection.delete(document.uri);

    const diagnostics = [];

    findings.forEach(finding => {
        // VS Code usa base 0 para líneas, el cli devuelve base 1
        const line = Math.max(0, finding.line - 1);
        const character = Math.max(0, finding.character);

        let lineText = '';
        try {
            lineText = document.lineAt(line).text;
        } catch (e) {}

        const startPos = new vscode.Position(line, character);
        // Resaltar la longitud de la evidencia o un carácter si no hay
        const matchLength = finding.evidence ? finding.evidence.length : 1;
        const endCharacter = Math.min(lineText.length, character + matchLength);
        const endPos = new vscode.Position(line, endCharacter);

        const range = new vscode.Range(startPos, endPos);

        // Mapear severidades
        let severity = vscode.DiagnosticSeverity.Information;
        if (finding.severity === 'high') {
            severity = vscode.DiagnosticSeverity.Error;
        } else if (finding.severity === 'medium') {
            severity = vscode.DiagnosticSeverity.Warning;
        }

        // Formato estructurado del tooltip del problema
        const message = 
`[${finding.rule_id}] ${finding.title}
--------------------------------------------------
Detalle:
${finding.description}

Evidencia:
"${finding.evidence}"

Recomendación de Remediación:
${finding.remediation}`;

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.code = finding.rule_id;
        diagnostic.source = 'OWASP Verificator';

        diagnostics.push(diagnostic);
    });

    collection.set(document.uri, diagnostics);
}

/**
 * @param {Array} findings 
 */
function updateStatusBar(findings) {
    const errors = findings.filter(f => f.severity === 'high').length;
    const warnings = findings.filter(f => f.severity === 'medium').length;
    const info = findings.filter(f => f.severity === 'low').length;

    if (errors > 0) {
        statusBarItem.text = `$(bug) OWASP: ${errors} error${errors > 1 ? 'es' : ''}`;
        statusBarItem.tooltip = `Se encontraron ${errors} problemas críticos de seguridad OWASP en este archivo.`;
        statusBarItem.color = new vscode.ThemeColor('statusBarItem.errorForeground');
    } else if (warnings > 0) {
        statusBarItem.text = `$(warning) OWASP: ${warnings} advertencia${warnings > 1 ? 's' : ''}`;
        statusBarItem.tooltip = `Se encontraron ${warnings} advertencias de seguridad OWASP en este archivo.`;
        statusBarItem.color = new vscode.ThemeColor('statusBarItem.warningForeground');
    } else if (info > 0) {
        statusBarItem.text = `$(info) OWASP: ${info} recomendación${info > 1 ? 'es' : ''}`;
        statusBarItem.tooltip = `Se encontraron ${info} recomendaciones menores en este archivo.`;
        statusBarItem.color = undefined;
    } else {
        statusBarItem.text = `$(check) OWASP: Seguro`;
        statusBarItem.tooltip = 'Cumplimiento OWASP verificado. No se detectaron problemas.';
        statusBarItem.color = undefined;
    }
}

function deactivate() {
    if (statusBarItem) {
        statusBarItem.dispose();
    }
}

module.exports = {
    activate,
    deactivate
};
