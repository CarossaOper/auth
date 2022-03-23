FROM node:16
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
ENV DB_URL="mongodb+srv://root:laho1472@cluster0.xxvir.mongodb.net/oper?retryWrites=true&w=majority"
EXPOSE 8082
CMD [ "npm" , "start" ]