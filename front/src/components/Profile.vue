<template>
  <div v-if="currentUser" class="container">
    <div class="alert alert-success admin" role="alert" style="text-align:center">
      <strong>{{ currentUser.username }}</strong> Profile
    </div>
    <div style="display:flex;justify-content: space-between;">
      <div>
        <ul class="list-group" style="width:fit-content">
          <li class="list-group-item d-flex align-items-center">
            <strong>Your id:</strong>
            <span class="badge badge-primary badge-pill">{{ currentUser.id }}</span>
          </li>
          <li class="list-group-item d-flex align-items-center">
            <strong>Your email:</strong>
            <span class="badge badge-primary badge-pill">{{ currentUser.email }}</span>
          </li>
          <li class="list-group-item d-flex align-items-center">
            <strong>Your authorities:</strong>
            <span class="badge badge-info badge-pill">{{ currentUser.roles[0] }}</span>
          </li>
          <li class="list-group-item d-flex align-items-center">
            <strong>Number of your points:</strong>
            <span class="badge badge-success badge-pill">{{ points.length }}</span>
            <button type="button" class="btn btn-outline-danger" @click="deletePoints()"> Delete <strong>all</strong>
              your
              points</button>
          </li>
        </ul>
      </div>
      <div class="card" style="width:40%;">
        <img class="card-img-top prof_image" alt="Card image cap" style="width:100%; height: 100px;">
        <div class="card-body">
          <p class="card-text">Modern responsive design Vue.JS Senior Developer</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import pointService from '../services/point.service';
export default {
  name: 'Profile',
  data() {
    return {
      points: []
    }
  },
  computed: {
    currentUser() {
      return this.$store.state.auth.user;
    }
  },
  methods: {
    getPoints() {
      pointService.getAll()
          .then(response => {
            this.points = response.data;
          })
          .catch(err => console.error(err))
    },
    deletePoints() {
      pointService.deleteAll();
      this.points = [];
    }
  },
  mounted() {
    if (!this.currentUser) {
      this.$router.push('/login');
    }
    this.getPoints();
  }
};
</script>

<style>
.list-group span {
  margin-left: 10px;
}
.list-group button {
  margin-left: 10px;
}
@media only screen and (max-width: 753px) {
  .prof_image {
    content: url("../../assets/cat.jpg")
  }
}
@media only screen and (min-width: 754px) and (max-width:1079px) {
  .prof_image {
    content: url("../../assets/kotik.jpeg")
  }
}
@media only screen and (min-width: 1080px) {
  .prof_image {
    content: url("../../assets/KOTYARA.jpg")
  }
}
</style>