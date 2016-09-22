import time
import os
import sys
sys.path.insert(0,'%s\Module'%os.getcwd())
import platform
import getpass
import time
import makehtml
import CountWarning

def Make():
  now = time.strftime("%c")
  if os.path.exists("Report/Report.html"):
    f = open("Report/Report.html","r+")
  else:
      f = open("Report/Report.html","w")

  war = CountWarning.warning()
  bad = CountWarning.notgood()
  good = CountWarning.ok()
  notconfig = CountWarning.notconfig()
  default = 215
  html_str ='''
    <style>
      .collapse
      {
        cursor: pointer;
        display: block;
        background: #F0F8FF;
      }
      .collapse + input
      {
        display: none; /* hide the checkboxes */
      }
      .collapse + input + div
      {
        display:none;
      }
      .collapse + input:checked + div
      {
        display:block;
      }
    @media print
    {
      #menu {
        display:none;
      }

    body {
      font-family: Verdana, Helvetica, sans-serif;
      }
    
    h1 {
      font-size: 13pt;
      font-weight:bold;
      margin:4pt 0pt 0pt 0pt;
      padding:0;
      }

    h2 {
      font-size: 12pt;
      font-weight:bold;
      margin:3pt 0pt 0pt 0pt;
      padding:0;
      }

    h3, a:link, a:visited {
      font-size: 9pt;
      font-weight:bold;
      margin:1pt 0pt 0pt 20pt;
      padding:0;
      text-decoration: none;
      color: #000000;
      }

    p,ul {
      font-size: 9pt;
      margin:1pt 0pt 8pt 40pt;
      padding:0;
      text-align:left;
      }

    li {
      font-size: 9pt;
      margin:0;
      padding:0;
      text-align:left;
      }

    td {
      border:0px;
      border-top:1px solid black;
      font-size: 9pt;
      }

    .head td {
      border:0px;
      font-weight:bold;
      font-size: 9pt;
      }
    .noprint { display: none; }
    }

  @media screen
  {
    body {
      font-family: Verdana, Helvetica, sans-serif;
      margin: 0px;
      background-color: #FFFFFF;
      color: #000000;
      text-align: center;
    }

    #container {
      text-align:left;
      margin: 10px auto;
      width: 90%;
    }

    h1 {
      font-family: Verdana, Helvetica, sans-serif;
      font-weight:bold;
      font-size: 14pt;
      color: #FFFFFF;
      background-color:#2A0D45;
      margin:10px 0px 0px 0px;
      padding:5px 4px 5px 4px;
      width: 100%;
      border:1px solid black;
      text-align: left;
    }

    h2 {
      font-family: Verdana, Helvetica, sans-serif;
      font-weight:bold;
      font-size: 11pt;
      color: #000000;
      margin:30px 0px 0px 0px;
      padding:4px;
      width: 100%;
      background-color:#F0F8FF;
      text-align: left;
    }

    h2.green {
      color: #000000;
      background-color:#CCFFCC;
      border-color:#006400;
    }

    h2.red {
      color: #000000;
      background-color:#FFCCCC;
      border-color:#8B0000;
    }
     
    h3 {
      font-family: Verdana, Helvetica, sans-serif;
      font-weight:bold;
      font-size: 10pt;
      color:#000000;
      background-color: #FFFFFF;
      width: 75%;
      text-align: left;
    }

    p {
      font-family: Verdana, Helvetica, sans-serif;
      font-size: 8pt;
      color:#000000;
      background-color: #FFFFFF;
      width: 75%;
      text-align: left;
    }

    p i {
      font-family: Verdana, Helvetica, sans-serif;
      font-size: 8pt;
      color:#000000;
      background-color: #CCCCCC;
    }

    ul {
      font-family: Verdana, Helvetica, sans-serif;
      font-size: 8pt;
      color:#000000;
      background-color: #FFFFFF;
      width: 75%;
      text-align: left;
    }

    a {
      font-family: Verdana, Helvetica, sans-serif;
      text-decoration: none;
      font-size: 8pt;
      color:#000000;
      font-weight:bold;
      background-color: #FFFFFF;
      color: #000000;
    }

    li a {
      font-family: Verdana, Helvetica, sans-serif;
      text-decoration: none;
      font-size: 10pt;
      color:#000000;
      font-weight:bold;
      background-color: #FFFFFF;
      color: #000000;
    }

    a:hover {
      text-decoration: underline;
    }

    a.up {
        color:#006400;
    }

    table {
      width: 80%;
      border:0px;
      color: #000000;
      background-color: #000000;
      margin:10px;
    }

    tr {
      vertical-align:top;
      font-family: Verdana, Helvetica, sans-serif;
      font-size: 8pt;
      color:#000000;
      background-color: #FFFFFF;
    }

    tr.head {
      background-color: #E1E1E1;
      color: #000000;
      font-weight:bold;
    }

    tr.open {
      background-color: #CCFFCC;
      color: #000000;
    }
    
    tr.script {
      background-color: #EFFFF7;
      color: #000000;
    }

    tr.filtered {
      background-color: #F2F2F2;
      color: #000000;
    }

    tr.closed {
      background-color: #F2F2F2;
      color: #000000;
    }
      
    td {
      padding:2px;
    }
          
    #menu li {
      display         : inline;
      margin          : 0;
      /*margin-right    : 10px;*/
      padding         : 0;
      list-style-type : none;
    }    
   
    #menubox {
      position: fixed;
      bottom: 0px;
      right: 0px;
      width: 120px;
    }
    .up {
      color: #000000;
      background-color:#CCFFCC;
    }
    
    .down {
      color:#626262;
      background-color: #F2F2F2;
    }

    .print_only { display: none; }
    .hidden { display: none; }
    .unhidden { display: block; }
    
  }
  </style>
    '''
  f.write(html_str)  
  stri = '''
  <body>
    <a name="top"></a><div id="container">
    <h1>Audit System Report - Scanned at %s</h1>
    <a name="scansummary"></a><hr class="print_only">
    <h2>Scan Summary</h2>
    <h3> System Infomation </h3>
    <ul>
    <li>OS Name : %s %s %s</li>
    <li>OS Version : %s</li>
    <li>System Name : %s</li>
    <li>User Name : %s/%s</li>
    <li>Machine Type : %s</li>
    <li>Processor Name : %s</li>
    </ul>
    <p></p>
    <h3>Statistic Results</h3>
    <ul>
    <li>Warning : %s</li>
    <li>Not Good : %s</li>
    <li>Good or OK : %s</li>
    <li>Not Config or Not Found : %s</li>
    <li>Default : %s</li>
    </ul>
    <h1> WARNING : %s </h1>
    <br />
    '''%(now,platform.system(),platform.release(),platform.win32_ver()[2],platform.version(),platform.uname()[1],platform.uname()[1],getpass.getuser(),platform.machine(),platform.processor(),war,bad,good,notconfig,default,war)
  f.write(stri)

  a = b = c = d = e = [0]
  a, b, c, d, e = makehtml.html()
  j=1
  k=2
  l=3
  m=4
  n=5
  for i in range(1,war+1):
    strin =''' 
      <label class="collapse" for="_%s">%s. %s</label>
      <input id="_%s" type="checkbox"> 
      <div> 
        <p align="center"><b>%s</b></hp> 
        <h3>Profile Applicability:</h3> 
          <p>%s %s %s</p> 
        <h3>Description: </h3> 
          <p>%s %s %s</p> 
        <h3>Remediation:</h3> 
            <p>%s %s %s</p> 
        </div>
        <br />
        '''%(i,i,a[j],i,a[k],' <br /> ',(' &nbsp; '*4),a[l],' <br /> ',(' &nbsp; '*4),a[m],' <br /> ',(' &nbsp; '*4),a[n])
    f.write(strin)
    j = j + 5
    k = k + 5
    l = l + 5
    m = m + 5
    n = n + 5
    sys.stdout.flush()
  f.close()