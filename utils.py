#===============================================================================================================
#---------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------
#------- Project: EVALUATION OF SQL INJECTION (SQLi) ATTACK DETECTION STRATEGIES IN WEB ------------------------
#------- APPLICATIONS USING MACHINE LEARNING -------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------
#------- By: Santiago Taborda Echeverri ------------------------------------------------------------------------
#-------     santiago.tabordae@udea.edu.co ---------------------------------------------------------------------
#-------     Telecommunications engineering student ------------------------------------------------------------
#-------     Cyber Security Analyst Intern at AizoOn Technology Consulting -------------------------------------
#---------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------
#===============================================================================================================

#===============================================================================================================
#------- libraries ---------------------------------------------------------------------------------------------
#===============================================================================================================
import re
import html
import base64
import binascii
import urllib.parse
import pandas as pd
import seaborn as sns
from joblib import dump
import matplotlib.pyplot as plt
from imblearn.over_sampling import RandomOverSampler
from imblearn.under_sampling import RandomUnderSampler
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score, recall_score, precision_score

#===============================================================================================================
#------- Data pre-processing -----------------------------------------------------------------------------------
#===============================================================================================================

def filter_logs(inputFilePath, outputFilePath):
    '''
    Function to filter the log entries retrieved from the WAF, taking into account only those corresponding
    to SQLi.
    Input:
    - path to the file with the WAF data.
    - File path to save the resulting csv file.
    Output:
    - Everything is saved to a csv file, no return.
    '''
    # Convert CSV file to pandas DataFrame
    df_raw = pd.read_csv(inputFilePath)
    
    # Recognition of logs starting with "942" (identifier for SQLi implemented in the WAF)
    index_logs = df_raw['rules.ruleid'].astype(str).str.startswith('942')

    # Creation of a dataframe only with the logs corresponding to SQLi
    filtered_df = df_raw[index_logs]

    # Cleaning NaN values
    filtered_df = filtered_df.dropna()
    
    # Save to an csv file
    filtered_df.to_csv(outputFilePath, index=False)

#===============================================================================================================

def extract_data_waf(inputfileRawPath, outputFilePath):
    '''
    Function to extract data from log entries retrieved from the WAF.
    Input:
    - file path of the file with the WAF data
    - file path to save the resulting csv file
    Output:
    - Everything is stored in a csv file, it has no return
    '''
    # Convert CSV file to pandas DataFrame
    df_raw = pd.read_csv(inputfileRawPath)

    # Empty DataFrame with the format of "information | label"
    clean_df = pd.DataFrame(columns=['Query'])

    # Extraction of information after the "ARGS" fragment using regex
    regex_expression = r'ARGS:[^:]*:\s(.*?)(?:Matched Data|, \(empty\),|, Blocked IP address|$)'
    clean_df['Query'] = df_raw['transaction.messages.details.data'].str.findall(regex_expression)

    # Transformation of list items extracted with regex into individual items in rows 
    clean_df = clean_df.explode('Query', ignore_index=True)

    # Assignment of the labels to the extracted information, attacks label=1
    clean_df['Label'] = 1

    # Cleaning NaN values
    clean_df = clean_df.dropna()

    # Save to an csv file
    clean_df.to_csv(outputFilePath, index=False)

#===============================================================================================================
"""
DECODER 

-taking into account the following general encoding formats:

Escape Unicode, Base 64, Hexadecimal, URL, Double url

-Additional allows decoding the following "tamper" exposed in the SQLMap tool:

apostrophemask, apostrophenullencode, appendnullbyte, base64encode, bluecoat, chardoubleencode, charencode, 
charunicodeencode, overlongutf8, percentage, symboliclogical, unmagicquotes
"""
def diffChar(string1:str, string2:str):
    """
    Function to compare two strings and calculate the number of different characters between them
    Input:
    - string1: First input string to compare
    - string2: Second input string to compare
    Output:
    - Returns the count of different characters between the two input strings.
    """
    # Convert input strings to sets to get unique characters
    set1 = set(string1)
    set2 = set(string2)
    
    # Find the symmetric difference between the two sets of different characters
    different_chars = set1.symmetric_difference(set2)
    
    # Return the count of different characters
    return len(different_chars)

def decode_overlongutf8(encoding_string):
    """
    Function to decode a UTF-8 overlong encoded string
    Input:
    - The "unicode encoding" (SQLMap reference) encoded string to decode
    Output:
    - Returns the decoded string
    """
    # Split the encoding string by '%'
    encoding_string = encoding_string.split('%')

    # Extract the hexadecimal strings
    hexadecimal_string1 = encoding_string[1]
    hexadecimal_string2 = encoding_string[2]

    # Convert the first hexadecimal string to integer
    original_value = int(hexadecimal_string1, 16) - 0xc0
    original_value <<= 6  # Shift left by 6 bits
    decoded_string1 = chr(original_value)# Convert the original value to a character

    # Convert the second hexadecimal string to integer and calculate the original value
    original_value = int(hexadecimal_string2, 16) - 0x80
    original_value &= 0x3f  # Apply bitmask to get the lower 6 bits
    decoded_string2 = chr(original_value)# Convert the original value to a character

    # Concatenate the decoded characters and return the decoded string
    return decoded_string1 + decoded_string2

def decode_data(encode_string:str):
    """
    Function to decode various types of encoded strings in a given input string
    Input:
    - The encoded string to decode
    Output:
    - Returns the decoded string after attempting to decode different types of encoding
    """
    
    # Regular expressions for detecting different types of encoding
    unicode_regex = re.compile(r'(?:\\|\%)(?:x[\da-fA-F]{2}|u[\da-fA-F]{4})') # Escape Unicode encoding
    base64_regex =  re.compile(r'[A-Za-z0-9+]{4,}={0,3}')                     # Base 64 encoding
    hexadecimal_regex = re.compile(r'0x([0-9A-Fa-f]+)')                       # Hexadecimal encoding
    url_regex = re.compile(r'((?:\%[0-9A-Fa-f]{2})+)')                        # URL encoding
    double_regex = re.compile(r'%[0-9A-Fa-f]{4}')                             # Double url encoding

    # Regular expressions for detecting different types of encoding SQLMap special
    percentage_regex = re.compile(r'((?:\%[\da-zA-Z]{1})+)(?=[\%\s]|$)')      # Percentage encoding
    unicodeMap_regex = re.compile(r'(\%C0\%[0-9A-Fa-f]{2})')                  # Unicode encoding
    and_regex = re.compile(r'((:?\%26\%26)+)')                                # symboliclogical encoding
    quotes_regex = re.compile(r'((:?\%bf\%27)+)')                             # unmagicquotes encoding
        

    temp_string=""
    decoded_string = encode_string
    try:
        while temp_string != decoded_string:
            temp_string = decoded_string

            # Search for HTML entity decoding
            if not html.unescape(decoded_string).__eq__(decoded_string):
                decoded_string = html.unescape(decoded_string)

            # Search for and encoding SQLMap tamper sequences
            and_match = and_regex.search(decoded_string)
            if and_match:
                # Get the start and end positions of the encoded portion of the string
                start_pos = and_match.start()
                end_pos = and_match.end()

                try:
                    and_line = " AND "

                    # Replace the decoded string in the final string with the decoded percentage characters
                    decoded_string = decoded_string[:start_pos] + and_line + decoded_string[end_pos:]
                    
                    # Force the program to jump to the next cycle if a decoding has been performed
                    continue
                except:
                    pass
            
            # Search for quotes encoding SQLMap tamper sequences
            quotes_match = quotes_regex.search(decoded_string)
            if quotes_match:
                # Get the start and end positions of the encoded portion of the string
                start_pos = quotes_match.start()
                end_pos = quotes_match.end()

                try:
                    quotes_line = "' "

                    # Replace the decoded string in the final string with the decoded percentage characters
                    decoded_string = decoded_string[:start_pos] + quotes_line + decoded_string[end_pos:]
                    
                    # Force the program to jump to the next cycle if a decoding has been performed
                    continue
                except:
                    pass

            # Search for double URL encoding
            double_match = double_regex.search(decoded_string)
            if double_match:
                # Get the start and end positions of the encoded portion of the string
                start_pos = double_match.start()
                end_pos = double_match.end()
                
                # Extract the double encoded string
                double_string = decoded_string[start_pos:end_pos]
                try:
                    # Decode the double string
                    double_line = urllib.parse.unquote(urllib.parse.unquote(double_string))
                    
                    # Check if there's a difference between the decoded double line and the original double string
                    if not double_line.__eq__(double_string) and double_line.isprintable():

                        # Replace the decoded string in the final string with the decoded double characters
                        decoded_string = decoded_string[:start_pos] + double_line + decoded_string[end_pos:]
                        
                        # Force the program to jump to the next cycle if a decoding has been performed
                        continue
                except:
                    pass

            # Search for Unicode encoded sequences
            unicode_match = unicode_regex.search(decoded_string)
            if unicode_match:
                # Get the start and end positions of the encoded portion of the string
                start_pos = unicode_match.start()
                end_pos = unicode_match.end()
                
                # Extract the Unicode encoded string
                unicode_string = decoded_string[start_pos:end_pos]
                
                # Replace "%u" with "\\u" to adjust to Python's Unicode escape sequence format
                unicode_string = unicode_string.replace("%u", "\\u")
                
                try:
                    # Decode the Unicode string
                    unicode_line = bytes(unicode_string, encoding="utf-8").decode("unicode-escape")
                    
                    # Check if there's a difference between the decoded Unicode line and the original Unicode string
                    if (diffChar(unicode_line, unicode_string) != 0) and unicode_line.isprintable():

                        # Replace the decoded string in the final string with the decoded Unicode characters
                        decoded_string = decoded_string[:start_pos] + unicode_line + decoded_string[end_pos:]
                        
                        # Force the program to jump to the next cycle if a decoding has been performed
                        continue
                except UnicodeDecodeError:
                    pass
            
            # Search for Unicode encoded as SQLMap tamper sequences
            unicodeMap_match = unicodeMap_regex.search(decoded_string)
            if unicodeMap_match:
                # Get the start and end positions of the encoded portion of the string
                start_pos = unicodeMap_match.start()
                end_pos = unicodeMap_match.end()
                
                # Extract the Unicode encoded string
                unicodeMap_string = decoded_string[start_pos:end_pos]
                
                try:
                    # Decode the Unicode string
                    unicodeMap_line = decode_overlongutf8(unicodeMap_string)
                    
                    # Check if there's a difference between the decoded Unicode line and the original Unicode string
                    if (diffChar(unicodeMap_line, unicodeMap_string) != 0) and unicodeMap_line.isprintable():

                        # Replace the decoded string in the final string with the decoded Unicode characters
                        decoded_string = decoded_string[:start_pos] + unicodeMap_line + decoded_string[end_pos:]
                        
                        # Force the program to jump to the next cycle if a decoding has been performed
                        continue
                except UnicodeDecodeError:
                    pass

            # Search for hexadecimal encoded sequences
            hexadecimal_match = hexadecimal_regex.search(decoded_string)
            if hexadecimal_match:
                # Get the start and end positions of the encoded portion of the string
                start_pos = hexadecimal_match.start()
                end_pos = hexadecimal_match.end()

                # Extract the Unicode encoded string
                hexadecimal_string = decoded_string[start_pos:end_pos]
                # Replace "0x" with "" to adjust to Python's hexadecimal sequence format
                hexadecimal_string = hexadecimal_string.replace("0x", "")
                hexadecimal_string = hexadecimal_string.replace("%", "")
                try:
                    # Decode the hexadecimal string
                    hexadecimal_line = binascii.a2b_hex(hexadecimal_string).decode()

                    # Check if there's a difference between the decoded hexadecimal line and the original hexadecimal string
                    if not hexadecimal_line.__eq__(hexadecimal_string):

                        # Replace the decoded string in the final string with the decoded hexadecimal characters
                        decoded_string = decoded_string[:start_pos] + hexadecimal_line + decoded_string[end_pos:]
                        
                        # Force the program to jump to the next cycle if a decoding has been performed
                        continue 
                except (binascii.Error, ValueError) as e:
                    pass
            
            # Search for url encoded sequences
            url_match = url_regex.search(decoded_string)
            if url_match:
                # Get the start and end positions of the encoded portion of the string
                start_pos = url_match.start()
                end_pos = url_match.end()

                # Extract the url encoded string
                url_string = decoded_string[start_pos:end_pos]
                try:
                    # Decode the url string
                    url_line =  urllib.parse.unquote(url_string)

                    # Check if there's a difference between the decoded url line and the original url string
                    if not url_line.__eq__(url_string) and url_line.isprintable():

                        # Replace the decoded string in the final string with the decoded url characters
                        decoded_string = decoded_string[:start_pos] + url_line + decoded_string[end_pos:]
                        
                        # Force the program to jump to the next cycle if a decoding has been performed
                        continue
                except:
                    pass
            
            # Search for all base64 sequences in the whole line that match with the regex
            base64_matches = base64_regex.finditer(decoded_string)
            if base64_matches:
                # Try to decode each one of the sequences (the match can be not base64 encoded)
                for base64_match in base64_matches:
                    # Get the start and end positions of the encoded portion of the string
                    start_pos = base64_match.start()
                    end_pos = base64_match.end()

                    # Extract the base64 encoded string
                    base64_string = decoded_string[start_pos:end_pos]
                    
                    padding_needed = len(base64_string) % 4
                    if padding_needed != 0:
                        base64_string += '=' * (4 - padding_needed)
                    try:
                        # Decode the base64 string
                        base64_line = base64.b64decode(base64_string).decode('utf-8')

                        # Check if there's a difference between the decoded base64 line and the original base64 
                        # string and if the decoded base64 has a printable string
                        if not base64_line.__eq__(base64_string) and base64_line.isprintable():

                            # Replace the decoded string in the final string with the decoded base64 characters
                            decoded_string = decoded_string[:start_pos] + base64_line + decoded_string[end_pos:]
                            
                            # Force the program to jump to the next cycle if a decoding has been performed
                            continue
                    except (binascii.Error, ValueError):
                        pass
            
            # Search for percentage encoding SQLMap tamper sequences
            percentage_match = percentage_regex.search(decoded_string)
            if percentage_match:
                # Get the start and end positions of the encoded portion of the string
                start_pos = percentage_match.start()
                end_pos = percentage_match.end()

                # Extract the percentage encoded string
                percentage_string = decoded_string[start_pos:end_pos]
                try:
                    percentage_line = percentage_string.replace("%", "")

                    # Check if there's a difference between the decoded percentage line and the original string
                    if not percentage_line.__eq__(percentage_string) and percentage_line.isprintable():

                        # Replace the decoded string in the final string with the decoded percentage characters
                        decoded_string = decoded_string[:start_pos] + percentage_line + decoded_string[end_pos:]
                        
                        # Force the program to jump to the next cycle if a decoding has been performed
                        continue
                except:
                    pass

            # Remove unnecessary characters
            if "\n" or "\t" or "\r" or "\x00" or "  " in decoded_string:
                decoded_string = decoded_string.replace("\n", "")   # new line
                decoded_string = decoded_string.replace("\t", " ")  # tab
                decoded_string = decoded_string.replace("\r", "")   # carriage return
                decoded_string = decoded_string.replace("\x00", "") # null
                decoded_string = decoded_string.replace("  ", " ")  # double spaces
                
    except (binascii.Error, ValueError):
        pass

    return decoded_string

#===============================================================================================================
def preprocess_input(data):
    """
    Function to pre-process data by performing specific transformations
    Input:
    - Data to pre-process
    Output:
    - Returns the pre-processed data after applying the following transformations in sequence:
        1. Replace URLs with a placeholder string 'http://u'.
        2. Replace emails by a generic representative string with value 'user@email'
        3. Decode data using the custom function decode_data.
        4. Remove non ASCII characters.
        5. Replace all digits with '0'.
        6. Convert all characters to lowercase.
        7. Insert spaces before and after special characters.
    """
    # Define a regular expression pattern to match URLs
    url_regex = re.compile(r'(?:https?|ftp|http):\/\/[\w\-]+(?:\.[\w\-]+)+[#?]?.*?(?=\s|$)')
    # Replace URLs with a placeholder string 'http://u'
    preprocess_data = url_regex.sub('http://u', data)

    # Define a regular expression pattern to match the Emails
    email_regex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    # Replace Emails with a placeholder string 'user@email'
    preprocess_data = email_regex.sub('user@email', data)  

    # Decode data using the custom function decode_data
    preprocess_data = decode_data(preprocess_data)       

    # Define a regular expression pattern to match non-ASCII characters
    non_Ascii_regex = re.compile(r'[^\x00-\x7F]')   
    # Remove non-ASCII characters
    preprocess_data = non_Ascii_regex.sub('', preprocess_data)           

    # Replace all digits with '0'
    zero_regex = re.compile(r'\d+')
    preprocess_data = zero_regex.sub(' 0 ', preprocess_data)            

    # Convert all characters to lowercase
    preprocess_data = preprocess_data.lower()                         

    # Define a regular expression pattern to match special characters
    specialChar_regex = re.compile(r'([^a-zA-Z0-9\s])')
    # Insert spaces before and after special characters
    preprocess_data = specialChar_regex.sub(r' \1 ', preprocess_data) 

    return preprocess_data

#===============================================================================================================
def process_input_analysis(data):
    """
    Function to process data by performing specific transformations to perform the statistical analysis
    Input:
    - Data to pre-process
    Output:
    - Returns the pre-processed data after applying the following transformations in sequence: 
        1. Remove punctuation.
        2. Remove all numbers.
    """

    # Define a regular expression pattern to match punctuation
    url_regex = re.compile(r'([^a-zA-Z0-9\s])')
    # Remove punctuation
    preprocess_data = url_regex.sub('', data)                   

    # Define a regular expression pattern to match digit numbers
    zero_regex = re.compile(r'\d+')
    # Remove numbers
    preprocess_data = zero_regex.sub('', preprocess_data)       

    # Split the data by blank space
    preprocess_data = preprocess_data.split()

    return preprocess_data

#===============================================================================================================
#------- Data processing ---------------------------------------------------------------------------------------
#===============================================================================================================

def NLP_transform(data, labels, outputFilePath):
    """
    Function to transform text data into a numerical representation using CountVectorizer
    Input:
    - The text data to transform
    - The corresponding labels for the text data
    Output:
    - Returns a DataFrame containing the vectorized representation of the input text data along with the labels
    """
    vectorizer = CountVectorizer() # Create a CountVectorizer object

    vectorizer = vectorizer.fit(data)

    # Vectorize the input data using the CountVectorizer and convert it to a dense array
    vectorized_data = vectorizer.transform(data).toarray()

    # Save the vectorizer to a file
    dump(vectorizer, outputFilePath) #'vectorizer.joblib'

    # Create a DataFrame from the vectorized data, with column names derived from the vectorizer
    vectorized_df = pd.DataFrame(data=vectorized_data, columns=vectorizer.get_feature_names_out())

    # Concatenate the vectorized DataFrame with the labels DataFrame along the columns (axis=1)
    vectorized_df = pd.concat([vectorized_df, labels], axis=1)

    return vectorized_df

#===============================================================================================================
def NLP_load_transform(data, labels, vectorizer):
    """
    Function to transform text data into a numerical representation using a model CountVectorizer gived
    Input:
    - The text data to transform
    - The corresponding labels for the text data
    Output:
    - Returns a DataFrame containing the vectorized representation of the input text data along with the labels
    """
    # Vectorize the input data using the CountVectorizer and convert it to a dense array
    vectorized_data = vectorizer.transform(data).toarray()

    # Create a DataFrame from the vectorized data, with column names derived from the vectorizer
    vectorized_df = pd.DataFrame(data=vectorized_data, columns=vectorizer.get_feature_names_out())

    # Concatenate the vectorized DataFrame with the labels DataFrame along the columns (axis=1)
    vectorized_df = pd.concat([vectorized_df, labels], axis=1)

    return vectorized_df

#===============================================================================================================
def balancing_data(X_data, y_data, balancing_type):
    """
    Function to balance input data using RandomOverSampler and RandomOverSampler
    Input:
    - The features of the input data
    - The labels of the input data
    - The method to use for balancing, options include 'RandomOverSampler' and 'RandomUnderSampler'
    Output:
    - Returns the balanced features (X_res) and labels (y_res) based on the specified balancing method
    """
    # Check if the balancing type is RandomOverSampler
    if balancing_type == 'RandomOverSampler':
        # Resample the data using the RandomOverSampler object
        random_over = RandomOverSampler(sampling_strategy='not majority', random_state=0)
        X_res, y_res = random_over.fit_resample(X_data, y_data)
        
    # Check if the balancing type is RandomUnderSampler
    if balancing_type == 'RandomUnderSampler':
        # Resample the data using the RandomUnderSampler object
        random_under = RandomUnderSampler(sampling_strategy="majority", random_state=0)
        X_res, y_res = random_under.fit_resample(X_data, y_data)

    return X_res, y_res

#===============================================================================================================
#------- AI Metrics --------------------------------------------------------------------------------------------
#===============================================================================================================

def metrics(model_name, test_data, pred_data, save_path_image):
    """
    Function to compute different AI metrics, display the confusion matrix and save it as .pdf
    Input:
    - Name of the model for which metrics are computed
    - True labels of the test data
    - Predicted labels of the test data
    - Classes used in the model
    Output:
    - Returns a list containing the model name and the metrics, and displays the confusion matrix.
    """
    accuracy = round(accuracy_score(test_data, pred_data), 4)
    balanced_accuracy = round(balanced_accuracy_score(test_data, pred_data), 4)
    precision = round(precision_score(test_data, pred_data), 4)
    recall = round(recall_score(test_data, pred_data), 4)
    f1 = round(f1_score(test_data, pred_data), 4)
    conf_matrix = confusion_matrix(test_data, pred_data)

    cmap = sns.cubehelix_palette(start=.2, rot=-.3, light=0.86, dark=0.3, as_cmap=True)
    sns.heatmap(conf_matrix, annot=True, cmap=cmap, cbar=False, linewidths=.5, fmt='g')

    # Adding axis labels and title
    plt.xlabel('Predicted Label', fontsize=16) #Predicted Label
    plt.ylabel('True Label', fontsize=16) #True Label

    # Customizing tick labels
    plt.xticks(ticks=[0.5, 1.5], labels=['No SQLi', 'SQLi'], fontsize=14)
    plt.yticks(ticks=[0.5, 1.5], labels=['No SQLi', 'SQLi'], fontsize=14)

    plt.tight_layout()

    plt.savefig(save_path_image, format="pdf", dpi=75, bbox_inches="tight")

    plt.show()

    return [model_name, accuracy, balanced_accuracy, precision, recall, f1]
