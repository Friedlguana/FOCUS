import cv2
import face_recognition
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

# Load known face encodings and names
known_face_encodings = []
known_face_names = ['Rijul', 'Ravi']

# Load the reference images for each face
reference_image_1 = face_recognition.load_image_file('test.jpg')
reference_face_encoding_1 = face_recognition.face_encodings(reference_image_1)[0]
known_face_encodings.append(reference_face_encoding_1)

reference_image_2 = face_recognition.load_image_file('test1.jpg')
reference_face_encoding_2 = face_recognition.face_encodings(reference_image_2)[0]
known_face_encodings.append(reference_face_encoding_2)

# Open the webcam
cap = cv2.VideoCapture(0)  # Use 0 for default webcam, 1 if you have an external one

tolerance = 0.5
r = 0
u = 0
while True:
    ret, frame = cap.read()

    if not ret:
        print("Error: Failed to capture a frame.")
        break

    face_locations = face_recognition.face_locations(frame)
    face_encodings = face_recognition.face_encodings(frame, face_locations)

    for (top, right, bottom, left), face_encoding in zip(face_locations, face_encodings):
        matches = face_recognition.compare_faces(known_face_encodings, face_encoding, tolerance=tolerance)
        name = "Unknown"
        
        if True in matches:
            first_match_index = matches.index(True)
            name = known_face_names[first_match_index]
        
        if name == 'Rijul':
            r+=1
            if r==10:
                print('Rijul detected')
                break  # Break when Rijul is detected
        elif name == 'Unknown':
            u += 1
            if u == 10:
                print('Unknown')
                break  # Break when Unknown is detected
            
        cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 0), 2)
        cv2.putText(frame, name, (left, top - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)

    cv2.imshow('Face Recognition', frame)
    if u == 5:
        cv2.destroyAllWindows()
        cv2.imwrite('photo.jpg', frame)
        smtp_port = 587
        smtp_server = "smtp.gmail.com"

        email_from = "aryamirani06@gmail.com"
        email_list = ["rijulravikumar@gmail.com", 'aryaamiranii@gmail.com']
        pswd = "xbxskelbiclhyjcz"
        subject = "UNAUTHORIZED LOGIN ATTEMPT !!"

        def send_emails(email_list):
            for person in email_list:
                body = f"""
                THIS PERSON TRIED TO ACCESS THE WHITELIST WITHOUT AUTHORIZATION """
                msg = MIMEMultipart()
                msg['From'] = email_from
                msg['To'] = person
                msg['Subject'] = subject

                msg.attach(MIMEText(body, 'plain'))

                filename = "photo.jpg"
                attachment = open(filename, 'rb')  # r for read and b for binary
                attachment_package = MIMEBase('application', 'octet-stream')
                attachment_package.set_payload((attachment).read())
                encoders.encode_base64(attachment_package)
                attachment_package.add_header('Content-Disposition', "attachment; filename= " + filename)
                msg.attach(attachment_package)

                text = msg.as_string()
                TIE_server = smtplib.SMTP(smtp_server, smtp_port)
                TIE_server.starttls()
                TIE_server.login(email_from, pswd)

                print()
                TIE_server.sendmail(email_from, person, text)
                print()

            TIE_server.quit()

        send_emails(email_list)
        break

    if r == 5:
        print('Rijul detected')
        os.startfile(r"Whitelisted Ports.txt")
        break
    
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()
