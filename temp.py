import pickle
import pandas as pd
from urllib.parse import urlparse
import ipaddress
import re
import clipboard
from tkinter import Frame,Label,Entry,Button,StringVar,Tk
import webbrowser

root =Tk()
root.configure(bg='#6787d6')

# setting the windows size
root.geometry("600x600")

loaded_model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))
    
# 1.Domain of the URL (Domain) 
def getDomain(url):  
  domain = urlparse(url).netloc
  if re.match(r"^www.",domain):
	       domain = domain.replace("www.","")
  return domain


# 2.Checks for IP address in URL (Have_IP)
def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip


# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
  if "@" in url:
    at = 1    
  else:
    at = 0    
  return at

# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
  if len(url) < 54:
    length = 0            
  else:
    length = 1            
  return length


# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth


# 6.Checking for redirection '//' in the url (Redirection)
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0


# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0

#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0


# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0            # legitimate



# importing required packages for this section
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime


# 10.DNS Record availability (DNS_Record)
# obtained in the featureExtraction function itself

# 11.Web traffic (Web_Traffic)
def web_traffic(url):
  try:
    #Filling the whitespaces in the URL if any
    url = urllib.parse.quote(url)
    rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
        "REACH")['RANK']
    rank = int(rank)
  except TypeError:
        return 1
  if rank <100000:
    return 1
  else:
    return 0


# 12.Survival time of domain: The difference between termination time and creation time (Domain_Age)  
def domainAge(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 1
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1
    else:
      age = 0
  return age

# 13.End time of domain: The difference between termination time and current time (Domain_End) 
def domainEnd(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  return end

# importing required packages for this section
import requests

# 14. IFrame Redirection (iFrame)
def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 0
      else:
          return 1

# 15.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response): 
  if response == "" :
    return 1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1
    else:
      return 0

# 16.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1

# 17.Checks the number of forwardings (Web_Forwards)    
def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1

#Function to extract features
def featureExtraction(url):
  print('called here')
  features = []
  
  #Address bar based features (10)
  #features.append(0)
  features.append(havingIP(url))
  features.append(haveAtSign(url))
  #features.append(getLength(url))
  #features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))
  
  #Domain based features (4)
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
  except:
    dns = 1
  features.append(dns)
  features.append(web_traffic(url))
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))
  
  # HTML & Javascript based features
  try:
    response = requests.get(url)
  except:
    response = ""

  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))
  features.append(forwarding(response))  
  
  legi_features = []
  legi_features.append(features)
    
  #converting the list to dataframe
  feature_names = ['Have_IP', 'Have_At','Redirection','https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                          'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards']
    
  urlclass = pd.DataFrame(legi_features,columns = feature_names)
    
  detect = loaded_model.predict(urlclass)
  
  if detect==0:
      print(1)
      outputlabel.configure(text= getDomain(url) + '\nis legitimate')
  else:
      temp = getDomain(url) + ' is phishing'
      " ".join(temp.split())
      if len(outputlabel['text']) > 20:
          outputlabel.configure(text= 'Above website \nis phishing')
      else:
          outputlabel.configure(text= getDomain(url) + '\nis phishing')
      
  return 0


def setTextInput(text):
    print(1)
    textEntry.set(text)

def callback(url):
    webbrowser.open_new(url)

def clearentry():
    url_entry.delete(0,'end')
    outputlabel.configure(text= 'Output will be shown here')
    
displayFrame = Frame(root,bg ='#6787d6')
displayFrame.pack()

detailsframe = Frame(displayFrame,bg='#d8dbe3')
detailsframe.pack(padx=40,pady=100)

desclabel= Label(detailsframe,text = 'Phishing Website Detection Using \n Machine Learning Techinque ',height=2,bg='#d8dbe3',font=('default',20))
desclabel.grid(columnspan=5)

asklabel= Label(detailsframe,text = 'Paste url to check',font=('default',14),bg='#d8dbe3',height=2)
asklabel.grid(row=1,padx=80,columnspan=5)

textEntry = StringVar()
url_entry = Entry(detailsframe,textvariable = textEntry,width=20,font=('default',12))
url_entry.grid(row = 2,column=1,columnspan=3,pady=10,rowspan=2)

pastebutton = Button(detailsframe,text='Paste',width=5,bg='#6787d6',font=('default',8),command=lambda:setTextInput(clipboard.paste()))
pastebutton.grid(row =2,column=3,pady=1,columnspan=2)

clearbutton = Button(detailsframe,text='Clear',width=5,bg='#de4b69',font=('default',8),command=lambda:clearentry())
clearbutton.grid(row =3,column=3,pady=1,columnspan=2)


checkbutton = Button(detailsframe,text='Check',width=10,bg='#6787d6',font=('default',13),command=lambda:featureExtraction(url_entry.get()))
checkbutton.grid(columnspan=5,pady=10)

outputlabel = Label(detailsframe,text='output will be shown here',font=('default',12),bg='#d8dbe3',height=2)
outputlabel.grid(padx=80,columnspan=5,pady=15)

link1 = Label(detailsframe, text="Know more about phishing", fg="blue", cursor="hand2",font=('default',12),bg='#d8dbe3',height=2)
link1.grid(columnspan=5,pady=10)
link1.bind("<Button-1>", lambda e: callback("https://en.wikipedia.org/wiki/Phishing"))


root.mainloop()
