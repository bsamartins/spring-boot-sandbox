package com.github.bsamartins.springboot.notifications.domain.persistence;

import com.github.bsamartins.springboot.notifications.domain.GroupCreate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.index.TextIndexed;
import org.springframework.data.mongodb.core.mapping.Document;

import javax.validation.constraints.NotNull;

@Document
public class Group {

    @Id
    private String id;

    @NotNull
    @Indexed(unique = true)
    @TextIndexed
    private String name;

    private String pictureId;

    public Group() {
    }

    public Group(Group other) {
        this.id = other.id;
        this.name = other.name;
        this.pictureId = other.pictureId;
    }

    public Group(GroupCreate other) {
        this.name = other.getName();
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPictureId() {
        return pictureId;
    }

    public void setPictureId(String pictureId) {
        this.pictureId = pictureId;
    }

    public String getPictureUri() {
        return String.format("http://localhost/api/files/%s", this.pictureId);
    }

}
