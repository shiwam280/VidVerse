import mongoose, {Schema} from "mongoose";


const likeSchema = new Schema({
    video:{
        type: Schema.Types.ObjectId,
        ref: "Video"
    },
    comment:{
        type: Schema.Types.ObjectId,
        ref: "Comment"
    },
    community:{
        type: Schema.Types.ObjectId,
        ref: "Community"
    },
    likedBy:{
        type: Schema.Types.ObjectId,
        ref: "User"
    }
}, {timestamps: true})

export const Like = mongoose.model("Like", likeSchema);