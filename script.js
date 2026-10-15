    function analyze(){


         let url=document.getElementById("scanner").value;
         if(url==" "||url==""){
            alert("Invalid URL!!");
            return;
         }
         
            url = url.replaceAll(" ","");
            url = url.toLowerCase();
            let domain = url;
            


            // url contains htpps:// protocol or not 
            let score = 0;
            if(url.includes("http://")){
                score += 10;
            }
            
            else if(!url.includes("https://")){
                url = "https://"+url;
            }

            
            // url length 
             
            if(url.length > 80 && url.length < 119){
                score += 8;
                document.getElementById("indicator-1").textContent="⚠ The URL is unusually long";
            }
            if(url.length >119){
                score +=15;
                document.getElementById("indicator-1").textContent="⚠ The URL is unusually long";
            }

            // keywords analyzers 

            if(url.includes("@")){
                score +=20;
                document.getElementById("indicator-2").textContent="⚠ The URL contains @.";
            }

            let keywords = ['login','verification','secure','update','password','banking','claim','free','urgent','verify','account','security','confirm','signin','wallet','bonus','gift'];
                let key_count=0;              
            for(let i=0; i<17;i++){
                    if(url.includes(keywords[i])){
                        key_count++;
                    }
                }
                if(key_count == 1 || key_count == 2){

                    score+=8;
                    document.getElementById("indicator-3").textContent="⚠ Suspicious keywords detected.";
                }
                if(key_count >=3){

                    score+=20;
                    document.getElementById("indicator-3").textContent="⚠ Multiple suspicious keywords detected";
                }

                
            // hyphens check (-)

            let hyphen = url.split("-").length-1;
            if(hyphen > 3){
                score +=10;
                document.getElementById("indicator-4").textContent="⚠ The domain contains many hyphens.";
            }

            // domain and subdomains

            
            let subdomain = url.split(".").length-2;
            if(subdomain>3){
                score+=15;
                document.getElementById("indicator-5").textContent="⚠ The URL contains many subdomains.";

            }

            // Query Parameeters

            let para = url.split("&");
            if(para.length>5){
                score +=10;
                document.getElementById("indicator-5").textContent="⚠ The URL contains many query parameters.";
            }

            // apk files 
            let download_files = ['.exe','.apk','ipa','msi'];
            let download_files_count =0 ;
            
            for(let i = 0; i<download_files.length;i++){
                if(url.includes(download_files[i])){
                    download_files_count++;

                }
            }
            if(download_files_count >= 1){
                score+=20;
                document.getElementById("indicator-6").textContent="⚠ Suspicious file extensions detected.";
            }


            // score implimentation 


            //upper box 3 
             if(url.length > 80 && url.length<120){
                document.getElementById("scan-url-1").style.fontSize="16px";
                document.getElementById("risk-score-1").style.fontSize="16px";
                document.getElementById("risk-level").style.fontSize="16px";
                document.getElementById("over2-2").style.width="250px";
            }
            else if(url.length >= 120){
                document.getElementById("scan-url-1").style.fontSize="14px";
                document.getElementById("risk-score-1").style.fontSize="14px";
                document.getElementById("risk-level").style.fontSize="14px";
                document.getElementById("over2-2").style.width="250px";
            }
            document.getElementById("scan-url-1").textContent=url;
            document.getElementById("risk-score-1").textContent=score;
            


            // upper box 1
            document.getElementById("result-score-1").textContent=score;
            // upper box 2
            if(score >=0 && score<30){
                document.getElementById("risk-type").textContent="Low Risk";
                document.getElementById("risk-level").textContent="Low ";
                document.getElementById("risk-type-element").textContent="✓ Low Risk";
                document.getElementById("risk-type-title").textContent="This URL does not contain many suspicious characteristics.";
                document.getElementById("risk-type").style.color="#40d978";
                document.getElementById("risk-type-element").style.color="#40d978";
                document.getElementById("risk-type-element").style.borderColor="#40d978";
                document.getElementById("risk-type-element").style.background=" rgba(50, 210, 115, 0.12)";
                
            }
            else if(score >=30 && score<60){
                document.getElementById("risk-type").textContent="Medium Risk";
                document.getElementById("risk-level").textContent= "Medium";
                document.getElementById("risk-type-element").textContent="⚠ Medium Risk";
                document.getElementById("risk-type-title").textContent="This URL contains some characteristics that deserve additional attention.";
                document.getElementById("risk-type").style.color="#f59e3a";
                document.getElementById("risk-type-element").style.color="#f59e3a";
                document.getElementById("risk-type-element").style.borderColor="#f59e3a";
                document.getElementById("risk-type-element").style.background=" rgba(242, 152, 79, 0.86)";
            }
            else{
                document.getElementById("risk-type").textContent="High Risk";
                document.getElementById("risk-level").textContent="High";
                document.getElementById("risk-type-element").textContent="⚠ High Risk";
                document.getElementById("risk-type-title").textContent="This URL contains multiple suspicious characteristics. Exercise caution.";
                document.getElementById("risk-type").style.color="#ff5050";
                document.getElementById("risk-type-element").style.color="#ff5050";
                document.getElementById("risk-type-element").style.borderColor="#ff5050";
                document.getElementById("risk-type-element").style.background="  rgba(255, 65, 65, 0.12)";
            }
            
            // lower box 2
            if(url.includes("https://")){
            document.getElementById("over1-1").textContent="https://";
            }
            else if(url.includes("http://")){
                document.getElementById("over1-1").textContent="http://";
            }
            else{
                document.getElementById("over1-1").textContent="Not Provided";
            }

            document.getElementById("over2-2").textContent=domain;
            document.getElementById("over3-3").textContent=url.length + "Chacracters";
            if(subdomain<=0){
            document.getElementById("over4-4").textContent="0";
            }
            else{
            document.getElementById("over4-4").textContent=subdomain;
            }

            if(score == 0){
                document.getElementById("indicator-1").textContent="✓ No suspicious indicators detected.";
                document.getElementById("indicator-1").style.color="#40d978";
            }


            // animation 
            if(score ==0){
                document.getElementById("display-anim").style.border="15px solid rgb(32, 34, 43)";
            }
            else if(score >0 && score<26){
                document.getElementById("display-anim").style.border="15px solid  rgb(32, 34, 43)";
                document.getElementById("display-anim").style.borderTop="15px solid #159eff";
            }
             else if(score >25 && score<51){
                document.getElementById("display-anim").style.border="15px solid  rgb(32, 34, 43)";
                document.getElementById("display-anim").style.borderTop="15px solid #159eff";
                document.getElementById("display-anim").style.borderRight="15px solid #159eff";
            }
            else if(score >50 && score<76){
                document.getElementById("display-anim").style.border="15px solid rgb(32, 34, 43)";
                document.getElementById("display-anim").style.borderTop="15px solid #159eff";
                document.getElementById("display-anim").style.borderRight="15px solid #159eff";
                document.getElementById("display-anim").style.borderBottom="15px solid #159eff";
            }
            else{
                document.getElementById("display-anim").style.border="15px solid green";

            }
            
            
            document.getElementById("Scanner-main-box").style.display = "block";

            document.getElementById("Scanner-main-box").scrollIntoView({
                behavior: "smooth",
                block: "start"
            });



            

          
            



        





        }// function bracket 




            