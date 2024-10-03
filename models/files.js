import mongoose, { Schema } from "mongoose";

const pdfschema = new mongoose.Schema({
   pdf: String,
   title: String
});

const pdfmodel = mongoose.model("pdfcollection", pdfschema);

export default pdfmodel;